// 输入和输出被加密，就像使用 128 位 ofb 模式一样。
// 用于记录我们使用了多少 128 位块的额外状态信息包含在 *num 中
void ofb128_encrypt(const unsigned char *in, unsigned char *out,
                    size_t len, const void *key,
                    unsigned char ivec[16], int *num, fptr_block128_t block)
{
  unsigned int n;
  size_t l = 0;

  if (*num < 0)
  {
    *num = -1;
    return;
  }
  n = *num;

#if !defined(SMALL_FOOTPRINT)
  if (16 % sizeof(size_t) == 0)
  {
    do
    {
      while (n && len)
      {
        *(out++) = *(in++) ^ ivec[n];
        --len;
        n = (n + 1) % 16;
      }
#if defined(STRICT_ALIGNMENT)
      if (((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) !=
          0)
        break;
#endif
      while (len >= 16)
      {
        (*block)(ivec, ivec, key);
        for (; n < 16; n += sizeof(size_t))
          *(mycrypt_size_t *)(out + n) =
              *(mycrypt_size_t *)(in + n) ^ *(mycrypt_size_t *)(ivec + n);
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
          out[n] = in[n] ^ ivec[n];
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
    out[l] = in[l] ^ ivec[n];
    ++l;
    n = (n + 1) % 16;
  }

  *num = n;
}
