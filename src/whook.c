#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <whook.h>

static LIST_HEAD(_w_hooks_head, w_hook) w_hooks;
static char *w_hook_script;

void w_hook_set_file(const char *file)
{
   if(w_hook_script)
      free(w_hook_script);

   w_hook_script = strdup(file);
}

char *w_hook_get_file()
{
   return w_hook_script;
}

void w_hook_event_start(struct w_hook_desc *w)
{
   struct w_hook *hook;

   w_log_printf("Hook: Received start event");

   LIST_FOREACH(hook, &w_hooks, link) {
      hook->start(w);
   }
}

void w_hook_event_stop(struct w_hook_desc *w)
{
   struct w_hook *hook;

   w_log_printf("Hook: Received stop event");

   LIST_FOREACH(hook, &w_hooks, link) {
      hook->stop(w);
   }
}

void w_hook_event_error(struct w_hook_desc *w, int error)
{
   struct w_hook *hook;

   w_log_printf("Hook: Received error event");

   LIST_FOREACH(hook, &w_hooks, link) {
      hook->error(w, error);
   }
}

void w_hook_event_data(struct w_hook_desc *w, int8_t d, char **data, size_t *len)
{
   struct w_hook *hook;

   w_log_printf("Hook: Received data event");

   LIST_FOREACH(hook, &w_hooks, link) {
      hook->data(w, d, data, len);
   }

   return;
}

void w_register_hook(struct w_hook *hook, struct w_hook_conf *whc)
{
   cmsg("Registering hook: %s", hook->name);

   LIST_INSERT_HEAD(&w_hooks, hook, link);
	hook->init(whc);
}

void w_hooks_init()
{
   cmsg("Initializing hooks");
	LIST_INIT(&w_hooks);

   w_rbhook_init();
}

void w_hooks_exit()
{
   cmsg("Exiting hooks");

	return;
}
