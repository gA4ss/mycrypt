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

    ret = p = (char*)OPENSSL_malloc(len + 1);

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

static const char *a_str[] = {
  "121",NULL
};

static const char *b_str[] = {
  "11",NULL
};

int main(int argc, char *argv[])
{
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  // BIGNUM *q = BN_new();
  BIGNUM *r = BN_new();

  // parse_bigBN(&a, a_str);
  // char *s = BN_bn2hex(a);
  // std::cout << s << std::endl;

  parse_bigBN(&a, a_str);
  char *s = BN_bn2hex(a);
  std::cout << s << std::endl;

  parse_bigBN(&b, b_str);
  s = BN_bn2hex(b);
  std::cout << s << std::endl;

  BN_CTX *ctx = BN_CTX_new();
  BN_gcd(r, a, b, ctx);
  s = BN_bn2hex(r);
  std::cout << s << std::endl;

  BN_clear_free(a);
  BN_clear_free(b);
  BN_clear_free(r);

  BN_CTX_free(ctx);
  return 0;
}