#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

static int initialized;
static FILE *logf;

void w_log_printf(const char *msg, ...)
{
   static char buff[65535];
   va_list va;

   if(!initialized)
      return;

   va_start(va, msg);
   vsnprintf(buff, sizeof(buff) - 1, msg, va);
   va_end(va);

   fprintf(logf, "%s\n", buff);
}

void w_log_write(const char *data, size_t len)
{
   if(!initialized)
      return;

   fwrite(data, len, 1, logf);
}

void w_log_init()
{
   char *ptr;

   ptr = getenv("WIREPLAY_LOG_FILE");
   if(!ptr)
      ptr = "wireplay.log";

   logf = fopen(ptr, "a");
   assert(logf != NULL);

   initialized = 1;
}

void w_log_deinit()
{
   if(!initialized)
      return;

   fclose(logf);
}
