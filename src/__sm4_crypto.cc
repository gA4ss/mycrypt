//
// 导入sm4的算法
//
#include "__sm4_key.cc"
#include "__sm4_cipher.cc"
#include "__sm4_overlapping.cc"

// int sm4_init(sm4_cipher_t &ctx, int m, int enc,
//              unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
// {
//   return ctx.init(m, key, iv, enc);
// }

int sm4_init_encrypt(sm4_cipher_t &ctx, int m,
             unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
{
  return ctx.init(m, key, iv, 1);
}

int sm4_init_decrypt(sm4_cipher_t &ctx, int m,
             unsigned char key[sm4_block_size], unsigned char iv[sm4_block_size])
{
  return ctx.init(m, key, iv, 0);
}

int sm4_cipher_update(sm4_cipher_t &ctx, unsigned char *input, size_t inlen,
                      unsigned char *output, size_t *outlen)
{
  int bl = ctx.block_size, cmpl = inlen;

  if (__is_partially_overlapping(output + ctx.buf_len, input, cmpl))
  {
    return -1;
  }

  if (ctx.buf_len == 0 && (inlen & (ctx.block_mask)) == 0)
  {
    if (ctx.do_cipher(output, input, inlen) == 0)
    {
      *outlen = inlen;
      return 0;
    }
    else
    {
      *outlen = 0;
      return -1;
    }
  }

  int i = ctx.buf_len, j = 0;

  mycrypt_assert(bl <= (int)sizeof(ctx.buf),
                 "block size '%d' must be less than buffer size '%d'.",
                 bl, (int)sizeof(ctx.buf));

  if (i != 0)
  {
    if ((size_t)(bl - i) > inlen)
    {
      memcpy(&(ctx.buf[i]), input, inlen);
      ctx.buf_len += inlen;
      *outlen = 0;
      return 0;
    }
    else
    {
      j = bl - i;

      //
      // 处理完in的前j个字节后
      // 剩余的数据是块长度的倍数: (l - j) & ~(l - 1)
      // 我们必须确保这个数据量，加上一个块大小
      // 从ctx->buf[i]处理，但不超过INT_MAX
      //
      if (((inlen - j) & ~(bl - 1)) > INT_MAX - (size_t)bl)
      {
        return -1;
      }
      memcpy(&(ctx.buf[i]), input, j);
      inlen -= j;
      input += j;
      if (ctx.do_cipher(output, ctx.buf, bl))
        return -1;
      output += bl;
      *outlen = bl;
    }
  }
  else
    *outlen = 0;
  i = inlen & (bl - 1);
  inlen -= i;
  if (inlen > 0)
  {
    if (ctx.do_cipher(output, input, inlen))
      return -1;
    *outlen += inlen;
  }

  if (i != 0)
    memcpy(ctx.buf, &(input[inlen]), i);
  ctx.buf_len = i;
  return 0;
}

int sm4_encrypt_update(sm4_cipher_t &ctx, unsigned char *input, size_t inlen,
                       unsigned char *output, size_t *outlen)
{
  if (outlen != nullptr)
  {
    *outlen = 0;
  }
  else
  {
    return -1;
  }

  // 检查是否是加密
  if (!ctx.encrypt)
  {
    return -1;
  }
  return sm4_cipher_update(ctx, input, inlen, output, outlen);
}

int sm4_decrypt_update(sm4_cipher_t &ctx, unsigned char *input, size_t inlen,
                       unsigned char *output, size_t *outlen)
{
  int fix_len;

  if (output != nullptr)
  {
    *output = 0;
  }
  else
  {
    return -1;
  }

  // 解密中，不能提供加密标志
  if (ctx.encrypt)
  {
    return -1;
  }

  unsigned int blocksize = ctx.block_size;
  mycrypt_assert(blocksize <= sizeof(ctx.final),
                 "blocksize '%d' must be less or equal final buffer size '%d'.",
                 blocksize, (int)sizeof(ctx.final));

  if (ctx.final_used)
  {
    /* 比较输入输出的缓冲 */
    if (((PTRDIFF_T)output == (PTRDIFF_T)input) ||
        __is_partially_overlapping(output, input, blocksize))
    {
      return -1;
    }

    //
    // 仅当buf_len为0时才设置final_used。因此，我们从sm4_cipher_update
    // 看到的最大长度输出是 <= inl 的块长度的最大倍数，
    // 或者只是：inlen & ~(b - 1) * 由于 final_used 已设置，
    // 因此最终输出长度为： * (inlen & ~(b - 1)) + b * 这绝不能超过 INT_MAX
    //
    if ((inlen & ~(blocksize - 1)) > INT_MAX - blocksize)
    {
      return -1;
    }
    memcpy(output, ctx.final, blocksize);
    output += blocksize;
    fix_len = 1;
  }
  else
    fix_len = 0;

  if (sm4_cipher_update(ctx, input, inlen, output, outlen))
    return -1;

  //
  // 如果我们解密多个块，确定我们有最后一个块的拷贝。
  //
  if (blocksize > 1 && !ctx.buf_len)
  {
    *outlen -= blocksize;
    ctx.final_used = 1;
    memcpy(ctx.final, &output[*outlen], blocksize);
  }
  else
    ctx.final_used = 0;

  if (fix_len)
    *outlen += blocksize;

  return 0;
}

int sm4_encrypt_final(sm4_cipher_t &ctx, unsigned char *output, size_t *outlen)
{
  if (outlen != nullptr)
  {
    *outlen = 0;
  }
  else
  {
    return -1;
  }

  if (!ctx.encrypt)
  {
    return -1;
  }

  int blocksize = ctx.block_size;
  mycrypt_assert(blocksize <= (int)sizeof(ctx.buf),
                 "blocksize '%d' must be less or equal buffer size '%d'.",
                 blocksize, (int)sizeof(ctx.buf));
  if (blocksize == 1)
  {
    *outlen = 0;
    return -1;
  }
  int buf_len = ctx.buf_len;
  int n = blocksize - buf_len;

  for (int i = buf_len; i < blocksize; i++)
    ctx.buf[i] = n;
  int ret = ctx.do_cipher(output, ctx.buf, blocksize);

  if (!ret)
    *outlen = blocksize;

  return ret;
}

int sm4_decrypt_final(sm4_cipher_t &ctx, unsigned char *output, size_t *outlen)
{

  if (outlen != nullptr)
  {
    *outlen = 0;
  }
  else
  {
    return -1;
  }

  if (ctx.encrypt)
  {
    return -1;
  }

  int blocksize = ctx.block_size;
  if (blocksize > 1)
  {
    if (ctx.buf_len || !ctx.final_used)
    {
      return -1;
    }
    mycrypt_assert(blocksize <= (int)sizeof(ctx.final),
                   "blocksize '%d' must be less or equal than final buffer size '%d'.",
                   blocksize, (int)sizeof(ctx.final));

    // 以下假设密文已通过认证，否则提供填充。
    int n = ctx.final[blocksize - 1];
    if (n == 0 || n > blocksize)
    {
      return -1;
    }
    for (int i = 0; i < n; i++)
    {
      if (ctx.final[--blocksize] != n)
      {
        return -1;
      }
    }
    n = ctx.block_size - n;
    for (int i = 0; i < n; i++)
      output[i] = ctx.final[i];
    *outlen = (size_t)n;
  }
  else
    *outlen = 0;
  return 0;
}