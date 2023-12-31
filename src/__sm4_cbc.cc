void cbc128_encrypt(const unsigned char *in, unsigned char *out,
                    size_t len, const void *key,
                    unsigned char ivec[16], fptr_block128_t block)
{
    size_t n;
    const unsigned char *iv = ivec;

    if (len == 0)
      return;

#if !defined(SMALL_FOOTPRINT)
  if (STRICT_ALIGNMENT &&
      ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      while (len >= 16) {
        for (n = 0; n < 16; ++n)
          out[n] = in[n] ^ iv[n];
        (*block) (out, out, key);
        iv = out;
        len -= 16;
        in += 16;
        out += 16;
      }
  } else {
    while (len >= 16) {
      for (n = 0; n < 16; n += sizeof(size_t))
        *(mycrypt_size_t *)(out + n) =
          *(mycrypt_size_t *)(in + n) ^ *(mycrypt_size_t *)(iv + n);
      (*block) (out, out, key);
      iv = out;
      len -= 16;
      in += 16;
      out += 16;
    }
  }
#endif
  while (len) {
    for (n = 0; n < 16 && n < len; ++n)
      out[n] = in[n] ^ iv[n];
    for (; n < 16; ++n)
      out[n] = iv[n];
    (*block) (out, out, key);
    iv = out;
    if (len <= 16)
      break;
    len -= 16;
    in += 16;
    out += 16;
  }
  if (ivec != iv)
    memcpy(ivec, iv, 16);
}

void cbc128_decrypt(const unsigned char *in, unsigned char *out,
                    size_t len, const void *key,
                    unsigned char ivec[16], fptr_block128_t block)
{
  size_t n;
  union {
    size_t t[16 / sizeof(size_t)];
    unsigned char c[16];
  } tmp;

  if (len == 0)
    return;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
  if (in != out) {
    const unsigned char *iv = ivec;

    if (STRICT_ALIGNMENT &&
      ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      while (len >= 16) {
        (*block) (in, out, key);
        for (n = 0; n < 16; ++n)
            out[n] ^= iv[n];
        iv = in;
        len -= 16;
        in += 16;
        out += 16;
      }
    } else if (16 % sizeof(size_t) == 0) { /* 应该总是对的 */
      while (len >= 16) {
        mycrypt_size_t *out_t = (mycrypt_size_t *)out;
        mycrypt_size_t *iv_t = (mycrypt_size_t *)iv;

        (*block) (in, out, key);
        for (n = 0; n < 16 / sizeof(size_t); n++)
          out_t[n] ^= iv_t[n];
        iv = in;
        len -= 16;
        in += 16;
        out += 16;
      }
    }
    if (ivec != iv)
      memcpy(ivec, iv, 16);
  } else {
    if (STRICT_ALIGNMENT &&
      ((size_t)in | (size_t)out | (size_t)ivec) % sizeof(size_t) != 0) {
      unsigned char c;
      while (len >= 16) {
        (*block) (in, tmp.c, key);
        for (n = 0; n < 16; ++n) {
          c = in[n];
          out[n] = tmp.c[n] ^ ivec[n];
          ivec[n] = c;
        }
        len -= 16;
        in += 16;
        out += 16;
      }
    } else if (16 % sizeof(size_t) == 0) { /* always true */
      while (len >= 16) {
        size_t c;
        mycrypt_size_t *out_t = (mycrypt_size_t *)out;
        mycrypt_size_t *ivec_t = (mycrypt_size_t *)ivec;
        const mycrypt_size_t *in_t = (const mycrypt_size_t *)in;

        (*block) (in, tmp.c, key);
        for (n = 0; n < 16 / sizeof(size_t); n++) {
          c = in_t[n];
          out_t[n] = tmp.t[n] ^ ivec_t[n];
          ivec_t[n] = c;
        }
        len -= 16;
        in += 16;
        out += 16;
      }
    }
  }
#endif
  while (len) {
    unsigned char c;
    (*block) (in, tmp.c, key);
    for (n = 0; n < 16 && n < len; ++n) {
      c = in[n];
      out[n] = tmp.c[n] ^ ivec[n];
      ivec[n] = c;
    }
    if (len <= 16) {
      for (; n < 16; ++n)
        ivec[n] = in[n];
      break;
    }
    len -= 16;
    in += 16;
    out += 16;
  }
}
