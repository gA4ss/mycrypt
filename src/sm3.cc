#include <mycrypt/sm3.h>
#include <cstring>

namespace mycrypt
{
  const static unsigned int sm3_cblock = 64;
  const static unsigned int sm3_lblock = (sm3_cblock/4);
  typedef unsigned int sm3_word_t;

#define sm3_a 0x7380166fUL
#define sm3_b 0x4914b2b9UL
#define sm3_c 0x172442d7UL
#define sm3_d 0xda8a0600UL
#define sm3_e 0xa96f30bcUL
#define sm3_f 0x163138aaUL
#define sm3_g 0xe38dee4dUL
#define sm3_h 0xb0fb0e4eUL

  typedef struct __sm3_state_t
  {
    sm3_word_t a, b, c, d, e, f, g, h;
    sm3_word_t nl, nh;
    sm3_word_t data[sm3_lblock];
    unsigned int num;

    __sm3_state_t()
    {
      a = sm3_a;
      b = sm3_b;
      c = sm3_c;
      d = sm3_d;
      e = sm3_e;
      f = sm3_f;
      g = sm3_g;
      h = sm3_h;
      nl = nh = num = 0;
      memset(data, 0, sm3_lblock * sizeof(sm3_word_t));
    }
  } sm3_state_t;

#define p0(x) (x ^ rotate(x, 9) ^ rotate(x, 17))
#define p1(x) (x ^ rotate(x, 15) ^ rotate(x, 23))

#define ff0(x,y,z) (x ^ y ^ z)
#define gg0(x,y,z) (x ^ y ^ z)

#define ff1(x,y,z) ((x & y) | ((x | y) & z))
#define gg1(x,y,z) ((z ^ (x & (y ^ z))))

#define expand(w0,w7,w13,w3,w10) \
  (p1(w0 ^ w7 ^ rotate(w13, 15)) ^ rotate(w3, 7) ^ w10)

#define rnd(a, b, c, d, e, f, g, h, tj, wi, wj, ff, gg)           \
  do {                                                            \
    const sm3_word_t a12 = rotate(a, 12);                         \
    const sm3_word_t a12_sm = a12 + e + tj;                       \
    const sm3_word_t ss1 = rotate(a12_sm, 7);                     \
    const sm3_word_t tt1 = ff(a, b, c) + d + (ss1 ^ a12) + (wj);  \
    const sm3_word_t tt2 = gg(e, f, g) + h + ss1 + wi;            \
    b = rotate(b, 9);                                             \
    d = tt1;                                                      \
    f = rotate(f, 19);                                            \
    h = p0(tt2);                                                  \
  } while(0)

#define r1(a,b,c,d,e,f,g,h,tj,wi,wj) \
  rnd(a,b,c,d,e,f,g,h,tj,wi,wj,ff0,gg0)

#define r2(a,b,c,d,e,f,g,h,tj,wi,wj) \
  rnd(a,b,c,d,e,f,g,h,tj,wi,wj,ff1,gg1)

  static int __sm3_init(sm3_state_t &ctx)
  {
    memset(&ctx, 0, sizeof(sm3_state_t));
    ctx.a = sm3_a;
    ctx.b = sm3_b;
    ctx.c = sm3_c;
    ctx.d = sm3_d;
    ctx.e = sm3_e;
    ctx.f = sm3_f;
    ctx.g = sm3_g;
    ctx.h = sm3_h;
    return 0;
  }

  //
  // 内部函数对sm3处理的数据进行字序转换
  // block data order
  //
  static inline void __sm3_transform(sm3_state_t &ctx, const void *p, size_t num)
  {
    const unsigned char *data = (const unsigned char *)p;
    register unsigned int a, b, c, d, e, f, g, h;

    unsigned int w00, w01, w02, w03, w04, w05, w06, w07,
      w08, w09, w10, w11, w12, w13, w14, w15;

    for (; num--;) {

      a = ctx.a;
      b = ctx.b;
      c = ctx.c;
      d = ctx.d;
      e = ctx.e;
      f = ctx.f;
      g = ctx.g;
      h = ctx.h;

      //
      // 我们不得不立即加载所有的消息数据，因为sm3读取他们
      //
      (void)c2l(data, w00);
      (void)c2l(data, w01);
      (void)c2l(data, w02);
      (void)c2l(data, w03);
      (void)c2l(data, w04);
      (void)c2l(data, w05);
      (void)c2l(data, w06);
      (void)c2l(data, w07);
      (void)c2l(data, w08);
      (void)c2l(data, w09);
      (void)c2l(data, w10);
      (void)c2l(data, w11);
      (void)c2l(data, w12);
      (void)c2l(data, w13);
      (void)c2l(data, w14);
      (void)c2l(data, w15);

      r1(a, b, c, d, e, f, g, h, 0x79CC4519, w00, w00 ^ w04);
      w00 = expand(w00, w07, w13, w03, w10);
      r1(d, a, b, c, h, e, f, g, 0xF3988A32, w01, w01 ^ w05);
      w01 = expand(w01, w08, w14, w04, w11);
      r1(c, d, a, b, g, h, e, f, 0xE7311465, w02, w02 ^ w06);
      w02 = expand(w02, w09, w15, w05, w12);
      r1(b, c, d, a, f, g, h, e, 0xCE6228CB, w03, w03 ^ w07);
      w03 = expand(w03, w10, w00, w06, w13);
      r1(a, b, c, d, e, f, g, h, 0x9CC45197, w04, w04 ^ w08);
      w04 = expand(w04, w11, w01, w07, w14);
      r1(d, a, b, c, h, e, f, g, 0x3988A32F, w05, w05 ^ w09);
      w05 = expand(w05, w12, w02, w08, w15);
      r1(c, d, a, b, g, h, e, f, 0x7311465E, w06, w06 ^ w10);
      w06 = expand(w06, w13, w03, w09, w00);
      r1(b, c, d, a, f, g, h, e, 0xE6228CBC, w07, w07 ^ w11);
      w07 = expand(w07, w14, w04, w10, w01);
      r1(a, b, c, d, e, f, g, h, 0xCC451979, w08, w08 ^ w12);
      w08 = expand(w08, w15, w05, w11, w02);
      r1(d, a, b, c, h, e, f, g, 0x988A32F3, w09, w09 ^ w13);
      w09 = expand(w09, w00, w06, w12, w03);
      r1(c, d, a, b, g, h, e, f, 0x311465E7, w10, w10 ^ w14);
      w10 = expand(w10, w01, w07, w13, w04);
      r1(b, c, d, a, f, g, h, e, 0x6228CBCE, w11, w11 ^ w15);
      w11 = expand(w11, w02, w08, w14, w05);
      r1(a, b, c, d, e, f, g, h, 0xC451979C, w12, w12 ^ w00);
      w12 = expand(w12, w03, w09, w15, w06);
      r1(d, a, b, c, h, e, f, g, 0x88A32F39, w13, w13 ^ w01);
      w13 = expand(w13, w04, w10, w00, w07);
      r1(c, d, a, b, g, h, e, f, 0x11465E73, w14, w14 ^ w02);
      w14 = expand(w14, w05, w11, w01, w08);
      r1(b, c, d, a, f, g, h, e, 0x228CBCE6, w15, w15 ^ w03);
      w15 = expand(w15, w06, w12, w02, w09);
      r2(a, b, c, d, e, f, g, h, 0x9D8A7A87, w00, w00 ^ w04);
      w00 = expand(w00, w07, w13, w03, w10);
      r2(d, a, b, c, h, e, f, g, 0x3B14F50F, w01, w01 ^ w05);
      w01 = expand(w01, w08, w14, w04, w11);
      r2(c, d, a, b, g, h, e, f, 0x7629EA1E, w02, w02 ^ w06);
      w02 = expand(w02, w09, w15, w05, w12);
      r2(b, c, d, a, f, g, h, e, 0xEC53D43C, w03, w03 ^ w07);
      w03 = expand(w03, w10, w00, w06, w13);
      r2(a, b, c, d, e, f, g, h, 0xD8A7A879, w04, w04 ^ w08);
      w04 = expand(w04, w11, w01, w07, w14);
      r2(d, a, b, c, h, e, f, g, 0xB14F50F3, w05, w05 ^ w09);
      w05 = expand(w05, w12, w02, w08, w15);
      r2(c, d, a, b, g, h, e, f, 0x629EA1E7, w06, w06 ^ w10);
      w06 = expand(w06, w13, w03, w09, w00);
      r2(b, c, d, a, f, g, h, e, 0xC53D43CE, w07, w07 ^ w11);
      w07 = expand(w07, w14, w04, w10, w01);
      r2(a, b, c, d, e, f, g, h, 0x8A7A879D, w08, w08 ^ w12);
      w08 = expand(w08, w15, w05, w11, w02);
      r2(d, a, b, c, h, e, f, g, 0x14F50F3B, w09, w09 ^ w13);
      w09 = expand(w09, w00, w06, w12, w03);
      r2(c, d, a, b, g, h, e, f, 0x29EA1E76, w10, w10 ^ w14);
      w10 = expand(w10, w01, w07, w13, w04);
      r2(b, c, d, a, f, g, h, e, 0x53D43CEC, w11, w11 ^ w15);
      w11 = expand(w11, w02, w08, w14, w05);
      r2(a, b, c, d, e, f, g, h, 0xA7A879D8, w12, w12 ^ w00);
      w12 = expand(w12, w03, w09, w15, w06);
      r2(d, a, b, c, h, e, f, g, 0x4F50F3B1, w13, w13 ^ w01);
      w13 = expand(w13, w04, w10, w00, w07);
      r2(c, d, a, b, g, h, e, f, 0x9EA1E762, w14, w14 ^ w02);
      w14 = expand(w14, w05, w11, w01, w08);
      r2(b, c, d, a, f, g, h, e, 0x3D43CEC5, w15, w15 ^ w03);
      w15 = expand(w15, w06, w12, w02, w09);
      r2(a, b, c, d, e, f, g, h, 0x7A879D8A, w00, w00 ^ w04);
      w00 = expand(w00, w07, w13, w03, w10);
      r2(d, a, b, c, h, e, f, g, 0xF50F3B14, w01, w01 ^ w05);
      w01 = expand(w01, w08, w14, w04, w11);
      r2(c, d, a, b, g, h, e, f, 0xEA1E7629, w02, w02 ^ w06);
      w02 = expand(w02, w09, w15, w05, w12);
      r2(b, c, d, a, f, g, h, e, 0xD43CEC53, w03, w03 ^ w07);
      w03 = expand(w03, w10, w00, w06, w13);
      r2(a, b, c, d, e, f, g, h, 0xA879D8A7, w04, w04 ^ w08);
      w04 = expand(w04, w11, w01, w07, w14);
      r2(d, a, b, c, h, e, f, g, 0x50F3B14F, w05, w05 ^ w09);
      w05 = expand(w05, w12, w02, w08, w15);
      r2(c, d, a, b, g, h, e, f, 0xA1E7629E, w06, w06 ^ w10);
      w06 = expand(w06, w13, w03, w09, w00);
      r2(b, c, d, a, f, g, h, e, 0x43CEC53D, w07, w07 ^ w11);
      w07 = expand(w07, w14, w04, w10, w01);
      r2(a, b, c, d, e, f, g, h, 0x879D8A7A, w08, w08 ^ w12);
      w08 = expand(w08, w15, w05, w11, w02);
      r2(d, a, b, c, h, e, f, g, 0x0F3B14F5, w09, w09 ^ w13);
      w09 = expand(w09, w00, w06, w12, w03);
      r2(c, d, a, b, g, h, e, f, 0x1E7629EA, w10, w10 ^ w14);
      w10 = expand(w10, w01, w07, w13, w04);
      r2(b, c, d, a, f, g, h, e, 0x3CEC53D4, w11, w11 ^ w15);
      w11 = expand(w11, w02, w08, w14, w05);
      r2(a, b, c, d, e, f, g, h, 0x79D8A7A8, w12, w12 ^ w00);
      w12 = expand(w12, w03, w09, w15, w06);
      r2(d, a, b, c, h, e, f, g, 0xF3B14F50, w13, w13 ^ w01);
      w13 = expand(w13, w04, w10, w00, w07);
      r2(c, d, a, b, g, h, e, f, 0xE7629EA1, w14, w14 ^ w02);
      w14 = expand(w14, w05, w11, w01, w08);
      r2(b, c, d, a, f, g, h, e, 0xCEC53D43, w15, w15 ^ w03);
      w15 = expand(w15, w06, w12, w02, w09);
      r2(a, b, c, d, e, f, g, h, 0x9D8A7A87, w00, w00 ^ w04);
      w00 = expand(w00, w07, w13, w03, w10);
      r2(d, a, b, c, h, e, f, g, 0x3B14F50F, w01, w01 ^ w05);
      w01 = expand(w01, w08, w14, w04, w11);
      r2(c, d, a, b, g, h, e, f, 0x7629EA1E, w02, w02 ^ w06);
      w02 = expand(w02, w09, w15, w05, w12);
      r2(b, c, d, a, f, g, h, e, 0xEC53D43C, w03, w03 ^ w07);
      w03 = expand(w03, w10, w00, w06, w13);
      r2(a, b, c, d, e, f, g, h, 0xD8A7A879, w04, w04 ^ w08);
      r2(d, a, b, c, h, e, f, g, 0xB14F50F3, w05, w05 ^ w09);
      r2(c, d, a, b, g, h, e, f, 0x629EA1E7, w06, w06 ^ w10);
      r2(b, c, d, a, f, g, h, e, 0xC53D43CE, w07, w07 ^ w11);
      r2(a, b, c, d, e, f, g, h, 0x8A7A879D, w08, w08 ^ w12);
      r2(d, a, b, c, h, e, f, g, 0x14F50F3B, w09, w09 ^ w13);
      r2(c, d, a, b, g, h, e, f, 0x29EA1E76, w10, w10 ^ w14);
      r2(b, c, d, a, f, g, h, e, 0x53D43CEC, w11, w11 ^ w15);
      r2(a, b, c, d, e, f, g, h, 0xA7A879D8, w12, w12 ^ w00);
      r2(d, a, b, c, h, e, f, g, 0x4F50F3B1, w13, w13 ^ w01);
      r2(c, d, a, b, g, h, e, f, 0x9EA1E762, w14, w14 ^ w02);
      r2(b, c, d, a, f, g, h, e, 0x3D43CEC5, w15, w15 ^ w03);

      ctx.a ^= a;
      ctx.b ^= b;
      ctx.c ^= c;
      ctx.d ^= d;
      ctx.e ^= e;
      ctx.f ^= f;
      ctx.g ^= g;
      ctx.h ^= h;
    }
  }

  static int __sm3_update(sm3_state_t &ctx, const void *ptr, size_t len)
  {
    const unsigned char *data = (const unsigned char *)ptr;
    unsigned char *p;
    sm3_word_t l;
    size_t n;

    if (len == 0)
      return -1;

    l = (ctx.nl + (((sm3_word_t) len) << 3)) & 0xffffffffUL;
    if (l < ctx.nl) // 溢出
      ctx.nh++;
    ctx.nh += (sm3_word_t) (len >> 29); /* 可能会造成编译器警告
                                        * 16位 */
    ctx.nl = l;

    n = ctx.num;
    if (n != 0) {
      p = (unsigned char *)ctx.data;

      if (len >= sm3_cblock || len + n >= sm3_cblock) {
        memcpy(p + n, data, sm3_cblock - n);
        __sm3_transform(ctx, p, 1);
        n = sm3_cblock - n;
        data += n;
        len -= n;
        ctx.num = 0;
        memset(p, 0, sm3_cblock);
      } else {
        memcpy(p + n, data, len);
        ctx.num += (unsigned int)len;
        return 0;
      }
    }

    n = len / sm3_cblock;
    if (n > 0) {
      __sm3_transform(ctx, data, n);
      n *= sm3_cblock;
      data += n;
      len -= n;
    }

    if (len != 0) {
      p = (unsigned char *)ctx.data;
      ctx.num = (unsigned int)len;
      memcpy(p, data, len);
    }
    return 0;
  }

#define __sm3_make_result(ctx, s)             \
  do {                                        \
    unsigned long ll;                         \
    ll=(ctx).a; (void)l2c(ll, (s));           \
    ll=(ctx).b; (void)l2c(ll, (s));           \
    ll=(ctx).c; (void)l2c(ll, (s));           \
    ll=(ctx).d; (void)l2c(ll, (s));           \
    ll=(ctx).e; (void)l2c(ll, (s));           \
    ll=(ctx).f; (void)l2c(ll, (s));           \
    ll=(ctx).g; (void)l2c(ll, (s));           \
    ll=(ctx).h; (void)l2c(ll, (s));           \
  } while (0)

  static int __sm3_final(sm3_state_t &ctx, unsigned char *md)
  {
    unsigned char *p = (unsigned char *)ctx.data;
    size_t n = ctx.num;

    p[n] = 0x80;    /* 结尾标志 */
    n++;

    if (n > (sm3_cblock - 8)) {
      memset(p + n, 0, sm3_cblock - n);
      n = 0;
      __sm3_transform(ctx, p, 1);
    }
    memset(p + n, 0, sm3_cblock - 8 - n);

    p += sm3_cblock - 8;
  # if   defined(IS_BIG_ENDIAN)
    (void)l2c(ctx.nh, p);
    (void)l2c(ctx.nl, p);
  # elif defined(IS_LITTLE_ENDIAN)
    (void)l2c(ctx.nl, p);
    (void)l2c(ctx.nh, p);
  # endif
    p -= sm3_cblock;
    __sm3_transform(ctx, p, 1);
    ctx.num = 0;
    memset(p, 0, sm3_cblock);

    // 产生最终结果
    __sm3_make_result(ctx, md);
    return 0;
  }

  int sm3(unsigned char *data, size_t datalen, unsigned char digest[sm3_digest_length])
  {
    sm3_state_t ctx;
    __sm3_update(ctx, data, datalen);
    __sm3_final(ctx, digest);
    return 0;
  }

//////////////////////////////////////////////////////////////////////////////////////////
  #include "__sm3_hmac.cc"

  int sm3_hmac (unsigned char *data, size_t datalen, unsigned char *key, size_t key_len, unsigned char mac[sm3_hmac_size])
  {
    if (!data || !key)
      return -1;
    sm3_hmac_state_t ctx;
    __sm3_hmac_init(ctx, key, key_len);
    __sm3_hmac_update(ctx, data, datalen);
    __sm3_hmac_final(ctx, mac);
    return 0;
  }

} // namespace mycrypt