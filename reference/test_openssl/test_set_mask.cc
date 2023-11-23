#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <iostream>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

static const char *a_str[] = {
    "55efe8",
    NULL};

int main(int argc, char *argv[])
{
  BIGNUM *a = BN_new();
  BIGNUM *r = BN_new();

  parse_bigBN(&a, a_str);
  char *s = BN_bn2hex(a);

  BN_mask_bits(a, 18);
  std::cout << BN_bn2hex(r) << std::endl;

  BN_clear_free(a);
  BN_clear_free(r);
  return 0;
}