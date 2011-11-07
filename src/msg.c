#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>

/*
 * eye-candy helpers
 */
static char _pb[65535];
inline void cfatal(const char *msg, ...)
{
   va_list va;

   va_start(va, msg);
   vsnprintf(_pb, sizeof(_pb) - 1, msg, va);
   va_end(va);

   fprintf(stderr, "[-] %s\n", _pb);
   exit(EXIT_FAILURE);
}

inline void cmsg(const char *msg, ...)
{
   va_list va;

   va_start(va, msg);
   vsnprintf(_pb, sizeof(_pb) - 1, msg, va);
   va_end(va);

   fprintf(stderr, "[*] %s\n", _pb);
}

inline void cmsg_up(const char *msg, ...)
{
   va_list va;

   va_start(va, msg);
   vsnprintf(_pb, sizeof(_pb) - 1, msg, va);
   va_end(va);

   fprintf(stderr, "\r[*] %s", _pb);
}

inline void cmsg_nl()
{
   fprintf(stderr, "\n");
}

inline void cmsg_raw(const char *msg, ...)
{
   va_list va;

   va_start(va, msg);
   vsnprintf(_pb, sizeof(_pb) - 1, msg, va);
   va_end(va);

   fprintf(stderr, "%s", _pb);
}
