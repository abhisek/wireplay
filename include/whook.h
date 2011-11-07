#ifndef _WIREPLAY_HOOK_H
#define _WIREPLAY_HOOK_H
#include <stdio.h>
#include <stdlib.h>
#include <queue.h>
#include <sys/types.h>
#include <inttypes.h>
#include <netinet/in.h>

/*
 * NOTE: This structure is one fancy shit I thought I'll implement.
 * Currently NOT USED in code logic
 */
struct w_hook_conf
{
	char *search_path;	/* The directory to search plugins for */
	char *ext;				/* The extension for plugins to load */
};

struct w_hook_desc
{
   in_addr_t host;      /* Remote Peer Host */
   in_port_t port;      /* Remote Peer Port */
   int role;
   int run_count;       /* Run count for session */
   void **p;            /* Private data */
};

struct w_hook
{
	char *name;
	void (*init)(struct w_hook_conf *whc);
	void (*start)(struct w_hook_desc *w);
	void (*data)(struct w_hook_desc *w, uint8_t d, char **dt, size_t *l);
	void (*stop)(struct w_hook_desc *w);
   void (*error)(struct w_hook_desc *w, int error);
	void (*deinit)();

	LIST_ENTRY(w_hook) link;
};

#endif
