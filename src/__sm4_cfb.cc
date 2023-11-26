// 输入和输出加密，就像使用128位cfb模式一样。记录我们有多少128位块的额外状态信息包含在*num中;
void cfb128_encrypt(const unsigned char *in, unsigned char *out,
                    size_t len, const void *key,
                    unsigned char ivec[16], int *num,
                    int enc, fptr_block128_t block)
{
  unsigned int n;
  size_t l = 0;

  if (*num < 0)
  {
    *num = -1;
    return;
  }
  n = *num;

  if (enc)
  {
#if !defined(SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0)
    {
      do
      {
        while (n && len)
        {
          *(out++) = ivec[n] ^= *(in++);
          --len;
          n = (n + 1) % 16;
        }
#if defined(STRICT_ALIGNMENT)
        if (((size_t)in | (size_t)out | (size_t)ivec) %
                sizeof(size_t) !=
            0)
          break;
#endif
        while (len >= 16)
        {
          (*block)(ivec, ivec, key);
          for (; n < 16; n += sizeof(size_t))
          {
            *(mycrypt_size_t *)(out + n) =
                *(mycrypt_size_t *)(ivec + n) ^= *(mycrypt_size_t *)(in + n);
          }
          len -= 16;
          out += 16;
          in += 16;
          n = 0;
        }
        if (len)
        {
          (*block)(ivec, ivec, key);
          while (len--)
          {
            out[n] = ivec[n] ^= in[n];
            ++n;
          }
        }
        *num = n;
        return;
      } while (0);
    }
#endif
    while (l < len)
    {
      if (n == 0)
      {
        (*block)(ivec, ivec, key);
      }
      out[l] = ivec[n] ^= in[l];
      ++l;
      n = (n + 1) % 16;
    }
    *num = n;
  }
  else
  {
#if !defined(SMALL_FOOTPRINT)
    if (16 % sizeof(size_t) == 0)
    {
      do
      {
        while (n && len)
        {
          unsigned char c;
          *(out++) = ivec[n] ^ (c = *(in++));
          ivec[n] = c;
          --len;
          n = (n + 1) % 16;
        }
#if defined(STRICT_ALIGNMENT)
        if (((size_t)in | (size_t)out | (size_t)ivec) %
                sizeof(size_t) !=
            0)
          break;
#endif
        while (len >= 16)
        {
          (*block)(ivec, ivec, key);
          for (; n < 16; n += sizeof(size_t))
          {
            size_t t = *(mycrypt_size_t *)(in + n);
            *(mycrypt_size_t *)(out + n) = *(mycrypt_size_t *)(ivec + n) ^ t;
            *(mycrypt_size_t *)(ivec + n) = t;
          }
          len -= 16;
          out += 16;
          in += 16;
          n = 0;
        }
        if (len)
        {
          (*block)(ivec, ivec, key);
          while (len--)
          {
            unsigned char c;
            out[n] = ivec[n] ^ (c = in[n]);
            ivec[n] = c;
            ++n;
          }
        }
        *num = n;
        return;
      } while (0);
    }
    /* 其余的通常会被 x86* 编译器消除 */
#endif
    while (l < len)
    {
      unsigned char c;
      if (n == 0)
      {
        (*block)(ivec, ivec, key);
      }
      out[l] = ivec[n] ^ (c = in[l]);
      ivec[n] = c;
      ++l;
      n = (n + 1) % 16;
    }
    *num = n;
  }
}

// 这需要一个大小为 nbits 的块用于输入和输出。请注意它会破坏 out 最后一个字节中的任何额外位
static void cfbr_encrypt_block(const unsigned char *in, unsigned char *out,
                               int nbits, const void *key,
                               unsigned char ivec[16], int enc,
                               fptr_block128_t block)
{
  int n, rem, num;
  unsigned char ovec[16 * 2 + 1]; /* +1 因为我们取消引用（但不使用）末尾一个字节 */

  if (nbits <= 0 || nbits > 128)
    return;

  /* 用当前 IV 填充新 IV 的前半部分 */
  memcpy(ovec, ivec, 16);
  /* 构造新的IV */
  (*block)(ivec, ivec, key);
  num = (nbits + 7) / 8;
  if (enc) /* 加密输入 */
    for (n = 0; n < num; ++n)
      out[n] = (ovec[16 + n] = in[n] ^ ivec[n]);
  else /* 解密输入 */
    for (n = 0; n < num; ++n)
      out[n] = (ovec[16 + n] = in[n]) ^ ivec[n];
  /* 左移. */
  rem = nbits % 8;
  num = nbits / 8;
  if (rem == 0)
    memcpy(ivec, ovec + num, 16);
  else
    for (n = 0; n < 16; ++n)
      ivec[n] = ovec[n + num] << rem | ovec[n + num + 1] >> (8 - rem);

  /* 没有必要清楚 ovec，因为 IV 不是秘密的 */
}

/* 这期望输入被打包，MS 位在前 */
void cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
                      size_t bits, const void *key,
                      unsigned char ivec[16], int *num,
                      int enc, fptr_block128_t block)
{
  size_t n;
  unsigned char c[1], d[1];

  for (n = 0; n < bits; ++n)
  {
    c[0] = (in[n / 8] & (1 << (7 - n % 8))) ? 0x80 : 0;
    cfbr_encrypt_block(c, d, 1, key, ivec, enc, block);
    out[n / 8] = (out[n / 8] & ~(1 << (unsigned int)(7 - n % 8))) |
                 ((d[0] & 0x80) >> (unsigned int)(n % 8));
  }
}

void cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
                      size_t length, const void *key,
                      unsigned char ivec[16], int *num,
                      int enc, fptr_block128_t block)
{
  size_t n;

  for (n = 0; n < length; ++n)
    cfbr_encrypt_block(&in[n], &out[n], 8, key, ivec, enc, block);
}
