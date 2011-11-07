#ifndef __WIREPLAY_H
#define __WIREPLAY_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <nids.h>
#include <queue.h>
#include <config.h>

struct tcp_session
{
   struct tuple4 tcp;
   uint32_t client_fd_seq;
   uint32_t server_fd_seq;

   LIST_ENTRY(tcp_session) link;
};

LIST_HEAD(tcp_session_list_head, tcp_session);

#define WIREPLAY_PROG_NAME       "Wireplay - The TCP Replay Tool"
#define WIREPLAY_PROG_URL        "http:\/\/code.google.com/p/wireplay/"
#define WIREPLAY_PROG_VER        "0.2"
#define WIREPLAY_COPYRIGHT       "Copyright (c) 2008,2009"

#define ROLE_CLIENT  1
#define ROLE_SERVER  2

#define REPLAY_SERVER_TO_CLIENT  0x01
#define REPLAY_CLIENT_TO_SERVER  0x02

#define ERROR_CONNECT_FAILED     0x01
#define ERROR_SEND_FAILED        0x02
#define ERROR_RECV_FAILED        0x03
#define ERROR_TIMEOUT            0x04
#define ERROR_SOCKET_ERROR       0x05  /* general purpose */

#endif
