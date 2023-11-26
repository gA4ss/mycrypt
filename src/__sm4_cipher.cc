#include <mycrypt/sm4.h>
#include <cstring>

namespace mycrypt
{

static const unsigned int max_key_length = 64;
static const unsigned int max_iv_length = 16;
static const unsigned int max_block_length = 32;

enum sm4_mode_t{
  mode_cbc = 0,
  mode_ecb = 1,
  mode_ofb = 2,
  mode_cfb = 3,
  mode_ctr = 4,
  max_mode_size = 5
};

  //
  // 模式的回调指针
  //
  typedef void (*fptr_block128_t) (const unsigned char in[16],
                                   unsigned char out[16], const void *key);

  typedef void (*fptr_cbc128_t) (const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key,
                                 unsigned char ivec[16], int enc);

  typedef void (*fptr_ecb128_t) (const unsigned char *in, unsigned char *out,
                                 size_t len, const void *key, int enc);

  typedef void (*fptr_ctr128_t) (const unsigned char *in, unsigned char *out,
                                 size_t blocks, const void *key,
                                 const unsigned char ivec[16]);

  typedef int (*fptr_do_cipher_t)(unsigned char *out, const unsigned char *in, size_t inl);

  #include "__sm4_cbc.cc"
  #include "__sm4_cfb.cc"
  #include "__sm4_ecb.cc"
  #include "__sm4_ofb.cc"
  #include "__sm4_ctr.cc"

  typedef struct __sm4_cipher_t {
    int mode;
    int encrypt;                              // 表明是加密还是解密

    int buf_len;                              // 预留的字节数
    int block_size;
    int key_len;
    int iv_len;
    int num;                                  // 在cfb/ofb/ctr模式中使用

    unsigned char oiv[max_iv_length];         // 原始的iv值
    unsigned char iv[max_iv_length];          // 使用中的iv值
    unsigned char buf[max_block_length];      // 保存不完全的块

    sm4_key_t ks;                             // sm4的算法
    fptr_block128_t block;
    //
    // 针对模式的优化回调函数
    //
    union {
      fptr_ecb128_t ecb;
      fptr_cbc128_t cbc;
      fptr_ctr128_t ctr;
      void *fptr;
    } stream;

    __sm4_cipher_t()
    {
      buf_len = block_size = key_len = iv_len = num = 0;

      memset(oiv, 0, max_iv_length);
      memset(iv, 0, max_iv_length);
      memset(buf, 0, max_block_length);

      block = nullptr;
      stream.fptr = nullptr;
    }

    int init(int m, const unsigned char *key, const unsigned char *iv, int enc)
    {
      mode = m;
      encrypt = enc;

      if ((mode == mode_ecb || mode == mode_cbc) && !encrypt)
      {
        block = (fptr_block128_t)sm4_decrypt;
        sm4_set_key(key, ks);
      }
      else
      {
        block = (fptr_block128_t)sm4_encrypt;
        sm4_set_key(key, ks);
      }

      //
      // 设置一些缓存大小
      //
      if (mode == mode_cbc)
      {
        block_size = 16;
        iv_len = 16;
      }
      else if (mode == mode_ecb)
      {
        block_size = 16;
        iv_len = 0;
      }
      else if (mode == mode_ofb)
      {
        block_size = 1;
        iv_len = 16;
      }
      else if (mode == mode_cfb)
      {
        block_size = 1;
        iv_len = 16;
      }
      else if (mode == mode_ctr)
      {
        block_size = 1;
        iv_len = 16;
      }
      key_len = 16;      // 128/8
      return 0;
    }

    int do_cipher(unsigned char *out, const unsigned char *in, size_t inl)
    {
      if (mode == mode_cbc) return __cbc_cipher(out, in, inl);
      else if (mode == mode_ecb) return __ecb_cipher(out, in, inl);
      else if (mode == mode_ofb) return __ofb_cipher(out, in, inl);
      else if (mode == mode_cfb) return __cfb_cipher(out, in, inl);
      else if (mode == mode_ctr) return __ctr_cipher(out, in, inl);
      return 0;
    }

    int __cbc_cipher(unsigned char *out, const unsigned char *in, size_t len)
    {
      // 如果存在优化的回调则执行
      if (stream.cbc)
        (stream.cbc)(in, out, len, &ks, iv, encrypt);
      else if (encrypt)
        cbc128_encrypt(in, out, len, &ks, iv, block);
      else
        cbc128_decrypt(in, out, len, &ks, iv, block);
      return 0;
    }

    int __cfb_cipher(unsigned char *out, const unsigned char *in, size_t len)
    {
      cfb128_encrypt(in, out, len, &ks, iv, &num, encrypt, block);
      return 0;
    }

    int __ecb_cipher(unsigned char *out, const unsigned char *in, size_t len)
    {
      if (len < (size_t)block_size)
        return -1;

      size_t i;
      if (stream.ecb != nullptr)
        (stream.ecb) (in, out, len, &ks, encrypt);
      else
        for (i = 0, len -= (size_t)block_size; i <= len; i += (size_t)block_size)
          block(in + i, out + i, &ks);

      return 0;
    }

    int __ofb_cipher(unsigned char *out, const unsigned char *in, size_t len)
    {
      ofb128_encrypt(in, out, len, &ks, iv, &num, block);
      return 0;
    }

    int __ctr_cipher(unsigned char *out,const unsigned char *in, size_t len)
    {
      if (num < 0)
        return -1;

      //
      // ctr模式没有优化代码
      //
      if (stream.ctr) ;
        // ctr128_encrypt_ctr32(in, out, len, &ks, iv, buf, (unsigned int *)&num, stream.ctr);
      else
        ctr128_encrypt(in, out, len, &ks, iv, buf, (unsigned int *)&num, block);
      return 0;
    }
  } sm4_cipher_t;
} // namespace mycrypt