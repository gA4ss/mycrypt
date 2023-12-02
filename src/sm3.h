#ifndef MYCRYPT_SM3_H_
#define MYCRYPT_SM3_H_

#include <mycrypt/common.h>
#include <cstdlib>

namespace mycrypt
{
  const static unsigned int sm3_digest_length = 32;
  const static unsigned int sm3_hmac_size = 32;

  int sm3(unsigned char *data, size_t datalen, unsigned char digest[sm3_digest_length]);
  int sm3_hmac(unsigned char *data, size_t datalen, unsigned char *key, size_t key_len, unsigned char mac[sm3_hmac_size]);
  int sm3_file(const char *path, unsigned char digest[sm3_digest_length]);
  int sm3_hmac_file(const char *path, unsigned char *key, size_t key_len, unsigned char mac[sm3_hmac_size]);
} // namespace mycrypt

#endif // MYCRYPT_SM3_H_