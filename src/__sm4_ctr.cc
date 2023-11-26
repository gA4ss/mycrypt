//
// 注意：IV/counter CTR模式是大端模式。代码本身是字节序中立的。
//
// typedef unsigned int u32;
// typedef unsigned char u8;
static void ctr128_inc(unsigned char *counter)
{
  unsigned int n = 16, c = 1;

  do
  {
    --n;
    c += counter[n];
    counter[n] = (unsigned char)c;
    c >>= 8;
  } while (n);
}

#if !defined(SMALL_FOOTPRINT)
static void ctr128_inc_aligned(unsigned char *counter)
{
  size_t *data, c, d, n;

  DECLARE_IS_ENDIAN;

  if (IS_LITTLE_ENDIAN || ((size_t)counter % sizeof(size_t)) != 0)
  {
    ctr128_inc(counter);
    return;
  }

  data = (size_t *)counter;
  c = 1;
  n = 16 / sizeof(size_t);
  do
  {
    --n;
    d = data[n] += c;
    /* 是否增加进位 */
    c = ((d - c) & ~d) >> (sizeof(size_t) * 8 - 1);
  } while (n);
}
#endif

//
// 输入被加密，就像使用 128 位计数器模式一样。
// *num 中包含用于记录我们使用了多少 128 位块的额外状态信息，
// 而加密计数器则保存在 ecount_buf 中。 *num 和 ecount_buf 都必须在第一次调用
// ctr128_encrypt() 之前用零初始化。
// 该算法假设计数器位于 IV (ivec) 的 x 个较低位，并且应用程序可以完全控制溢出和 IV 的其余部分。
// 此实现不负责检查计数器在递增时不会溢出到 IV 的其余部分。
//
void ctr128_encrypt(const unsigned char *in, unsigned char *out,
                    size_t len, const void *key,
                    unsigned char ivec[16],
                    unsigned char ecount_buf[16], unsigned int *num,
                    fptr_block128_t block)
{
  unsigned int n;
  size_t l = 0;

  n = *num;

#if !defined(SMALL_FOOTPRINT)
  if (16 % sizeof(size_t) == 0)
  {
    do
    {
      while (n && len)
      {
        *(out++) = *(in++) ^ ecount_buf[n];
        --len;
        n = (n + 1) % 16;
      }

#if defined(STRICT_ALIGNMENT)
      if (((size_t)in | (size_t)out | (size_t)ecount_buf) % sizeof(size_t) != 0)
        break;
#endif
      while (len >= 16)
      {
        (*block)(ivec, ecount_buf, key);
        ctr128_inc_aligned(ivec);
        for (n = 0; n < 16; n += sizeof(size_t))
          *(mycrypt_size_t *)(out + n) =
              *(mycrypt_size_t *)(in + n) ^ *(mycrypt_size_t *)(ecount_buf + n);
        len -= 16;
        out += 16;
        in += 16;
        n = 0;
      }
      if (len)
      {
        (*block)(ivec, ecount_buf, key);
        ctr128_inc_aligned(ivec);
        while (len--)
        {
          out[n] = in[n] ^ ecount_buf[n];
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
      (*block)(ivec, ecount_buf, key);
      ctr128_inc(ivec);
    }
    out[l] = in[l] ^ ecount_buf[n];
    ++l;
    n = (n + 1) % 16;
  }

  *num = n;
}

// // 将 128 位计数器的高 96 位加 1
// static void ctr96_inc(unsigned char *counter)
// {
//   u32 n = 12, c = 1;

//   do
//   {
//     --n;
//     c += counter[n];
//     counter[n] = (u8)c;
//     c >>= 8;
//   } while (n);
// }

// void ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
//                           size_t len, const void *key,
//                           unsigned char ivec[16],
//                           unsigned char ecount_buf[16],
//                           unsigned int *num, fptr_ctr128_t func)
// {
//   unsigned int n, ctr32;

//   n = *num;

//   while (n && len)
//   {
//     *(out++) = *(in++) ^ ecount_buf[n];
//     --len;
//     n = (n + 1) % 16;
//   }

//   ctr32 = GETU32(ivec + 12);
//   while (len >= 16)
//   {
//     size_t blocks = len / 16;

//     //
//     // 1<<28 只是一个不那么小但也不那么大的数字
//     // 下面的条件实际上永远不会满足，但必须检查代码的正确性。
//     //
//     if (sizeof(size_t) > sizeof(unsigned int) && blocks > (1U << 28))
//       blocks = (1U << 28);
    
//     // 由于 (*func) 在 32 位计数器上运行，调用者必须处理溢出。
//     // 下面的“if”检测到溢出，然后通过将块数量限制到确切的溢出点来处理。
//     ctr32 += (u32)blocks;
//     if (ctr32 < blocks)
//     {
//       blocks -= ctr32;
//       ctr32 = 0;
//     }
//     (*func)(in, out, blocks, key, ivec);
//     // *ctr 不更新ivec, 调用者自行处理
//     PUTU32(ivec + 12, ctr32);
//     // 溢出被检查到
//     if (ctr32 == 0)
//       ctr96_inc(ivec);
//     blocks *= 16;
//     len -= blocks;
//     out += blocks;
//     in += blocks;
//   }
//   if (len)
//   {
//     memset(ecount_buf, 0, 16);
//     (*func)(ecount_buf, ecount_buf, 1, key, ivec);
//     ++ctr32;
//     PUTU32(ivec + 12, ctr32);
//     if (ctr32 == 0)
//       ctr96_inc(ivec);
//     while (len--)
//     {
//       out[n] = in[n] ^ ecount_buf[n];
//       ++n;
//     }
//   }

//   *num = n;
// }
