#ifndef MYCRYPT_COMMON_H_
#define MYCRYPT_COMMON_H_

#include <mycrypt/compile.h>
#include <mycrypt/debug.h>
#include <mycrypt/exception.h>

namespace mycrypt
{

  // //
  // // 类型定义
  // //
  // typedef unsigned long long    u8;
  // typedef unsigned int          u4;
  // typedef unsigned short        u2;
  // typedef unsigned char         u1;

  // typedef struct
  // {
  //   u8 v[4];
  // } u32;

  // typedef struct __point_t
  // {
  //   u32 x;
  //   u32 y;
  // } point_t;

  //
  // 交换高低位
  //
#define rotate(a, n) (((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))

  //
  // 字序转换
  //
#if defined(IS_BIG_ENDIAN)

#define c2l(c, l) (l = (((unsigned long)(*((c)++))) << 24),  \
                   l |= (((unsigned long)(*((c)++))) << 16), \
                   l |= (((unsigned long)(*((c)++))) << 8),  \
                   l |= (((unsigned long)(*((c)++)))))
#define l2c(l, c) (*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
                   *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
                   *((c)++) = (unsigned char)(((l) >> 8) & 0xff),  \
                   *((c)++) = (unsigned char)(((l)) & 0xff),       \
                   l)

#elif defined(IS_LITTLE_ENDIAN)

#define c2l(c, l) (l = (((unsigned long)(*((c)++)))),        \
                   l |= (((unsigned long)(*((c)++))) << 8),  \
                   l |= (((unsigned long)(*((c)++))) << 16), \
                   l |= (((unsigned long)(*((c)++))) << 24))
#define l2c(l, c) (*((c)++) = (unsigned char)(((l)) & 0xff),       \
                   *((c)++) = (unsigned char)(((l) >> 8) & 0xff),  \
                   *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
                   *((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
                   l)

#endif

} // namespace mycrypt

#endif // MYCRYPT_COMMON_H_