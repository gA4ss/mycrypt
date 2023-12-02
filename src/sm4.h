#ifndef MYCRYPT_SM4_H_
#define MYCRYPT_SM4_H_

#include <mycrypt/common.h>

namespace mycrypt
{

  static const unsigned int sm4_block_size = 16;
  static const unsigned int sm4_key_schedule = 32;

  int sm4_ecb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size]);
  int sm4_ecb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size]);

  int sm4_cbc_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);
  int sm4_cbc_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);

  int sm4_cfb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);
  int sm4_cfb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);

  int sm4_ofb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);
  int sm4_ofb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);

  int sm4_ctr_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);
  int sm4_ctr_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size]);

} // namespace mycrypt

#endif // MYCRYPT_SM4_H_