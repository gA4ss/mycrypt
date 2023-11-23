// static const unsigned int hmac_max_md_cblock_size = 144;
static const unsigned int hmac_max_md_cblock_size = sm3_cblock;

typedef struct __sm3_hmac_state_t
{
  sm3_state_t sm3_ctx;
  unsigned char ipad[hmac_max_md_cblock_size];
  unsigned char opad[hmac_max_md_cblock_size];

  // ------------------------------
  __sm3_hmac_state_t()
  {
    memset(ipad, 0, hmac_max_md_cblock_size);
    memset(opad, 0, hmac_max_md_cblock_size);
  }
} sm3_hmac_state_t;

static int __sm3_hmac_init(sm3_hmac_state_t &ctx, unsigned char *key, unsigned int len)
{
  // unsigned char pad[hmac_max_md_cblock_size] = {0};
  unsigned int keytmp_length = 0;
  unsigned char keytmp[hmac_max_md_cblock_size] = {0};

  if (!key || len <= 0)
    return 1;

  if (len > sm3_cblock)
  {
    if (sm3(key, len, keytmp))
    {
      // FIXME : 异常
    }
    keytmp_length = sm3_digest_length;
  }
  else
  {
    // 密码在范围内
    memcpy(keytmp, key, len);
    keytmp_length = len;
  }

  mycrypt_assert(keytmp_length <= hmac_max_md_cblock_size, 
                 "keylen must be less than %lu.", hmac_max_md_cblock_size);

  //
  // 进行填充
  //
  if (keytmp_length != hmac_max_md_cblock_size)
    memset(&keytmp[keytmp_length], 0, hmac_max_md_cblock_size - keytmp_length);

  // 第一次填充
  for (unsigned int i = 0; i < hmac_max_md_cblock_size; i++)
    ctx.ipad[i] = 0x36 ^ keytmp[i];
  __sm3_update(ctx.sm3_ctx, ctx.ipad, sm3_cblock);

  // 第二次填充
  for (unsigned int i = 0; i < hmac_max_md_cblock_size; i++)
    ctx.opad[i] = 0x5c ^ keytmp[i];

  return 0;
}

static int __sm3_hmac_update(sm3_hmac_state_t &ctx, const unsigned char *data, size_t len)
{
  return __sm3_update(ctx.sm3_ctx, data, len);
}

static int __sm3_hmac_final(sm3_hmac_state_t &ctx, unsigned char *md)
{
  unsigned char salt[sm3_digest_length];

  if (!md)
    return -1;

  if (__sm3_final(ctx.sm3_ctx, salt))
    return -1;
  __sm3_init(ctx.sm3_ctx);
  __sm3_update(ctx.sm3_ctx, ctx.opad, sm3_cblock);
  __sm3_update(ctx.sm3_ctx, salt, sm3_digest_length);
  __sm3_final(ctx.sm3_ctx, md);
  return 0;
}
