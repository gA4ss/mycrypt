#ifndef MYCRYPT_SM4_H_
#define MYCRYPT_SM4_H_

#include <mycrypt/common.h>

namespace mycrypt
{
  static const unsigned int sm4_block_size = 16;
  static const unsigned int sm4_key_schedule = 32;

  typedef struct __sm4_key_t
  {
    uint32_t rk[sm4_key_schedule];
  } sm4_key_t;

  int sm4_set_key(const uint8_t *key, sm4_key_t &ks);
  void sm4_encrypt(const uint8_t *in, uint8_t *out, const sm4_key_t &ks);
  void sm4_decrypt(const uint8_t *in, uint8_t *out, const sm4_key_t &ks);

  int sm4_ctr(unsigned char * input, size_t len, unsigned char *output, 
              unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);

} // namespace mycrypt

#endif // MYCRYPT_SM4_H_