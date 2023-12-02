#include <mycrypt/sm4.h>
#include <climits>

namespace mycrypt
{
  #include "__sm4_crypto.cc"

  int sm4_ecb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size])
  {
    sm4_cipher_t ctx;
    sm4_init_encrypt(ctx, mode_ecb, key, {});
    ctx.encrypt = 1;

    size_t outlen = 0, enlen = 0;
    sm4_encrypt_update(ctx, input, len, output, &outlen);
    enlen = outlen;

    sm4_encrypt_final(ctx, output + outlen, &outlen);
    enlen += outlen;
    return (int)enlen;
  }
  int sm4_ecb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size])
  {
    sm4_cipher_t ctx;
    sm4_init_decrypt(ctx, mode_ecb, key, {});
    ctx.encrypt = 0;

    size_t outlen = 0, delen = 0;
    sm4_decrypt_update(ctx, input, len, output, &outlen);
    delen = outlen;

    sm4_decrypt_final(ctx, output + outlen, &outlen);
    delen += outlen;
    return (int)delen;
  }

  int sm4_cbc_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }
  int sm4_cbc_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }

  int sm4_cfb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }
  int sm4_cfb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }

  int sm4_ofb_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }
  int sm4_ofb_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }

  int sm4_ctr_encrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }
  int sm4_ctr_decrypt(unsigned char *input, size_t len, unsigned char *output,
                      unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
  {
    return 0;
  }

} // namespace mycrypt