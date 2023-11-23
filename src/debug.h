#ifndef MYCRYPT_DEBUG_H_
#define MYCRYPT_DEBUG_H_

#include <my/my_debug.h>
#include <mycrypt/compile.h>

namespace mycrypt
{

#ifdef DEBUG
#define mycrypt_dbgprint(s) my::dbgprint(__FILE__, __LINE__, __FUNCTION__, "%s", (s))
#define mycrypt_dbgprint_fmt(format, ...) my::dbgprint(__FILE__, __LINE__, __FUNCTION__, format, __VA_ARGS__)
#else
#define mycrypt_dbgprint(s)
#define mycrypt_dbgprint_fmt(format, ...)
#endif

} // namespace mycrypt

#endif // MYCRYPT_DEBUG_H_