#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// char *BN_bn2hex(const BIGNUM *a);
// char *BN_bn2dec(const BIGNUM *a);

// static const char *a_str[] = {
//     "AADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD112233",
//     "44FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA123",
//     "4DDCAADD11223344FFBCDEA1234DDCDDCCAABB1289232CCAABB1289232CCAABB",
//     "4DDCAADD11223344FFBCDEA1234DDCDDCCAABB1289232CCAABB1289232CCAABB",
//     "44FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA123",
//     "FFAADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD112233",
//     "FFAADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD112233",
//     "FFAADD11223344FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD112233",
//     "FFDDCCBB1234578436548278549091037548274903156042749036t8427489FF",
//     "19DD11223344FFBCDEA1234DDCAADD11223344FFBCDEA1234DDCAADD112233DD",
//     NULL
// };

char *glue_strings(const char *list[], size_t *out_len)
{
  size_t len = 0;
  char *p, *ret;
  int i;

  for (i = 0; list[i] != NULL; i++)
    len += strlen(list[i]);

  if (out_len != NULL)
    *out_len = len;

  ret = p = (char *)OPENSSL_malloc(len + 1);

  for (i = 0; list[i] != NULL; i++)
    p += strlen(strcpy(p, list[i]));

  return ret;
}

static int parse_bigBN(BIGNUM **out, const char *bn_strings[])
{
  char *bigstring = glue_strings(bn_strings, NULL);
  int ret = BN_hex2bn(out, bigstring);

  OPENSSL_free(bigstring);
  return ret;
}

struct bignum_st {
    BN_ULONG *d;                /*
                                 * Pointer to an array of 'BN_BITS2' bit
                                 * chunks. These chunks are organised in
                                 * a least significant chunk first order.
                                 */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

typedef struct bignum_st BIGNUM;


struct bn_mont_ctx_st {
    int ri;                     /* number of bits in R */
    BIGNUM RR;                  /* used to convert to montgomery form,
                                   possibly zero-padded */
    BIGNUM N;                   /* The modulus */
    BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
                                 * stored for bignum algorithm) */
    BN_ULONG n0[2];             /* least significant word(s) of Ni; (type
                                 * changed with 0.9.9, was "BN_ULONG n0;"
                                 * before) */
    int flags;
};

static BIGNUM nilbn;
void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    ctx->RR = nilbn;
    ctx->N = nilbn;
    ctx->Ni = nilbn;
    ctx->n0[0] = ctx->n0[1] = 0;
    ctx->flags = 0;
}

int my_BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
    int i, ret = 0;
    BIGNUM *Ri, *R;

    if (BN_is_zero(mod))
        return 0;

    BN_CTX_start(ctx);
    if ((Ri = BN_CTX_get(ctx)) == NULL)
        goto err;
    R = &(mont->RR);            /* grab RR as a temp */
    if (!BN_copy(&(mont->N), mod))
        goto err;               /* Set N */
    if (BN_get_flags(mod, BN_FLG_CONSTTIME) != 0)
        BN_set_flags(&(mont->N), BN_FLG_CONSTTIME);
    mont->N.neg = 0;
    {                           /* bignum version */
        mont->ri = BN_num_bits(&mont->N);
        BN_zero(R);
        if (!BN_set_bit(R, mont->ri))
            goto err;           /* R = 2^ri */
        /* Ri = R^-1 mod N */
        if ((BN_mod_inverse(Ri, R, &mont->N, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, mont->ri))
            goto err;           /* R*Ri */
        if (!BN_sub_word(Ri, 1))
            goto err;
        /*
         * Ni = (R*Ri-1) / N
         */
        if (!BN_div(&(mont->Ni), NULL, Ri, &mont->N, ctx))
            goto err;
    }
    /* setup RR for conversions */
    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri * 2))
        goto err;
    if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx))
        goto err;

    for (i = mont->RR.top, ret = mont->N.top; i < ret; i++)
        mont->RR.d[i] = 0;
    mont->RR.top = ret;
    mont->RR.flags |= 0;

    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

int my_bn_from_mont_fixed_top(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
                           BN_CTX *ctx)
{
    int retn = 0;
    BIGNUM *t1, *t2;

    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    if (!BN_copy(t1, a))
        goto err;
    BN_mask_bits(t1, mont->ri);

    if (!BN_mul(t2, t1, &mont->Ni, ctx))
        goto err;
    BN_mask_bits(t2, mont->ri);

    if (!BN_mul(t1, t2, &mont->N, ctx))
        goto err;
    if (!BN_add(t2, a, t1))
        goto err;
    if (!BN_rshift(ret, t2, mont->ri))
        goto err;

    if (BN_ucmp(ret, &(mont->N)) >= 0) {
        if (!BN_usub(ret, ret, &(mont->N)))
            goto err;
    }
    retn = 1;
    // bn_check_top(ret);
 err:
    BN_CTX_end(ctx);
    return retn;
}

int my_bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    BIGNUM *tmp;
    int ret = 0;
    int num = mont->N.top;

    if ((a->top + b->top) > 2 * num)
        return 0;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    // bn_check_top(tmp);
    if (a == b) {
        if (!BN_sqr(tmp, a, ctx))
            goto err;
    } else {
        if (!BN_mul(tmp, a, b, ctx))
            goto err;
    }
    /* reduce from aRR to aR */
    if (!my_bn_from_mont_fixed_top(r, tmp, mont, ctx))
        goto err;
    ret = 1;
 err:
    BN_CTX_end(ctx);
    return ret;
}

int my_BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret = my_bn_mul_mont_fixed_top(r, a, b, mont, ctx);
    return ret;
}

static const char *m_str[] = {
    "3f50d",
    NULL};

static const char *a_str[] = {
    "4d2",
    NULL};

static const char *b_str[] = {
    "11d4",
    NULL};

int main(int argc, char *argv[])
{
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *r = BN_new();
  BIGNUM *m = BN_new();

  parse_bigBN(&a, a_str);
  parse_bigBN(&b, b_str);
  parse_bigBN(&m, m_str);

  BN_CTX *ctx = BN_CTX_new();
  BN_MONT_CTX *mont = BN_MONT_CTX_new();
  BN_MONT_CTX_init(mont);
  my_BN_MONT_CTX_set(mont, m, ctx);
  my_BN_mod_mul_montgomery(r, a, b, mont, ctx);
  std::cout << BN_bn2hex(r) << std::endl;

  BN_clear_free(a);
  BN_clear_free(b);
  BN_clear_free(r);
  BN_clear_free(m);
  BN_MONT_CTX_free(mont);
  BN_CTX_free(ctx);
  return 0;
}