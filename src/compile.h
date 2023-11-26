#ifndef MYCRYPT_COMPILE_H_
#define MYCRYPT_COMPILE_H_

#include <mycrypt/endian.h>
#include <cstdlib>

namespace mycrypt
{

//
// 调试选项
//
// #define DEBUG      1
#ifdef DEBUG

#endif

//
// 严格对其
//
#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
#define STRICT_ALIGNMENT 0
#endif

#if defined(__GNUC__) && !STRICT_ALIGNMENT
  typedef size_t mycrypt_size_t __attribute((__aligned__(1)));
#else
  typedef size_t mycrypt_size_t;
#endif

//
// 加密算法每次递进单个单元
//
// #define SMALL_FOOTPRINT

} // namespace mycrypt

#endif // MYCRYPT_COMPILE_H_