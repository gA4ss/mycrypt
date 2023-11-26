#ifndef MYCRYPT_ENDIAN_H_
#define MYCRYPT_ENDIAN_H_
#pragma once

namespace mycrypt
{

  //
  // IS_LITTLE_ENDIAN和IS_BIG_ENDIAN可以用来检测端序
  // 在编译时。要使用它，必须使用DECLARE_IS_ENDIAN来声明
  // 一个变量。
  //
  // L_ENDIAN和B_ENDIAN可以在预处理器时使用。
  //

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
#define DECLARE_IS_ENDIAN const int __is_little_endian = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define IS_LITTLE_ENDIAN (__is_little_endian)
#define IS_BIG_ENDIAN (!__is_little_endian)
#if defined(L_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "L_ENDIAN defined on a big endian machine"
#endif
#if defined(B_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#error "B_ENDIAN defined on a little endian machine"
#endif
#if !defined(L_ENDIAN) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define L_ENDIAN
#endif
#if !defined(B_ENDIAN) && (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#define B_ENDIAN
#endif
#else
#define DECLARE_IS_ENDIAN \
  const union             \
  {                       \
    long one;             \
    char little;          \
  } __is_endian = {1}

#define IS_LITTLE_ENDIAN (__is_endian.little != 0)
#define IS_BIG_ENDIAN (__is_endian.little == 0)
#endif

} // namespace mycrypt

#endif // MYCRYPT_ENDIAN_H_