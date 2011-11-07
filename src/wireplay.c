#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <nids.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <wireplay.h>
#include <whook.h>
#include <debug.h>

static uint8_t role;
static char *pd_file;
static uint32_t replay_count;
static uint32_t enable_log;
static int run_count;
static int nids_no_cksum;
static int sock_timeout_ms;
static int sock_simulate;
static int sock_reconn;
static int sock_reconn_count;
static int sock_reconn_wait;

/*
 * TCP session identifiers
 */
static in_addr_t src_host;
static in_addr_t dst_host;
static in_port_t src_port;
static in_port_t dst_port;
static uint32_t server_fd_seq;
static uint32_t client_fd_seq;
/*
 * Target details when playing client mode
 */
static in_addr_t target_host;
static in_port_t target_port;

/*
 * TCP Stream list for selection
 */
static int max_tcp_streams;
static struct tcp_session_list_head tcp_sessions;

/*
 * Relay sockets
 */
static int csock;
static int bsock;

/*
 * Session state
 */
static int session_started;
static int server_data_count;
static int client_data_count;

/*
 * Data structure use for relay
 */
struct {
	char *data;
	char *new_data;
	size_t len;
	size_t newlen;
} client_data;

struct {
	char *data;
	char *new_data;
	size_t len;
	size_t newlen;
} server_data;

/*
 * Function prototype
 */
static void w_event_session_start();
static void w_event_session_data(uint8_t direction);
static void w_event_session_stop();
static void w_stop_replay();


/*
 * nids counters used for relaying
 */
static int cdata;
static int sdata;

/*
 * hook desc
 */
static struct w_hook_desc whd;

static void help()
{
   FILE *fp;

   fp = stderr;
   
   fprintf(fp, "%s v%s\n", WIREPLAY_PROG_NAME, WIREPLAY_PROG_VER);
   fprintf(fp, "\n");
   fprintf(fp, "Options:\n");
   fprintf(fp, "\t-r       --role    [ROLE]       Specify the role to play (client/server)\n");
   fprintf(fp, "\t-F       --file    [FILE]       Specify the pcap dump file to read packets\n");
   fprintf(fp, "\t-t       --target  [TARGET]     Specify the target IP to connect to when in client role\n");
   fprintf(fp, "\t-p       --port    [PORT]       Specify the port to connect/listen\n");
   fprintf(fp, "\t-S       --shost   [SOURCE]     Specify the source host for session selection\n");
   fprintf(fp, "\t-D       --dhost   [DEST]       Specify the destination host for session selection\n");
   fprintf(fp, "\t-E       --sport   [SPORT]      Specify the source port for session selection\n");
   fprintf(fp, "\t-G       --dport   [DPORT]      Specify the destination port for session selection\n");
   fprintf(fp, "\t-n       --isn     [ISN]        Specify the TCP ISN for session selection\n");
   fprintf(fp, "\t-c       --count   [NUMBER]     Specify the number of times to repeat the replay\n");
   fprintf(fp, "\t-H       --hook    [FILE]       Specify the Ruby script to load as hook\n");
   fprintf(fp, "\t-L       --log                  Enable logging (default path: $(PWD)/wireplay.log)\n");
   fprintf(fp, "\t-K       --disable-checksum     Disable NIDS TCP checksum verification\n");
   fprintf(fp, "\t-T       --timeout [MS]         Set socket read timeout in microsecond\n");
   fprintf(fp, "\t-Q       --simulate             Simulate Socket I/O only, do not send/recv\n");
   fprintf(fp, "\t-R       --reconnect            Enable reconnect attempt if connect fails (only in client role)\n");
   fprintf(fp, "\t-C       --rcount               Specify the number of times to attempt reconnect\n");
   fprintf(fp, "\n\n");

   fprintf(fp, "In case the --shost && --dhost && --isn && --sport && --dport parameters are not supplied, \n");
   fprintf(fp, "the program will load all the TCP sessions from file and ask the user to select a session to\n");
   fprintf(fp, "replay\n\n");

   exit(EXIT_FAILURE);
}

/*
 * sigsegv handler for broken libnids
 */
static void segv_handler1(int signo)
{
   fprintf(stderr, "\n"
                   "You probably using a broken version of libnids <= 1.23 for which it crashed\n"
                   "on second nids_init() at process_tcp() in tcp.c in libnids source code.\n"
                   "Apply the patch in lp/ and recompile libnids to fix the issue.\n"
                   "\n");
   
   __asm__(
      "xorl %eax, %eax\n"
      "incl %eax\n"
      "movl %eax, %ebx\n"
      "int $0x80\n"
   );
}

/*
 * ctrl+C handler
 */
static void sigint_handler1(int signo)
{
   cmsg("Exiting on SIGINT");
   exit(EXIT_FAILURE);
}

/*
 * Initialize default configuration options
 */
static void conf_init()
{
   pd_file = "pcap/pcap.dump";
   max_tcp_streams = 1024;
   replay_count = 1;

   sock_timeout_ms = 500000;  /* 5 second timeout by default */
   sock_simulate = 0;   /* disabled by default */

   sock_reconn = 0;  /* disable by default */
   sock_reconn_count = 3;
   sock_reconn_wait = 5;

   return;
}

/*
 * Read and process command line arguments
 */
static void conf_get_cmdline(int argc, char **argv)
{
   int oi;
   int c;
   static struct option lops[] = {
      {"role", 1, 0, 'r'},
      {"file", 1, 0, 'F'},
      {"target", 1, 0, 't'},
      {"port", 1, 0, 'p'},
      {"shost", 1, 0, 'S'},
      {"dhost", 1, 0, 'D'},
      {"sport", 1, 0, 'E'},
      {"dport", 1, 0, 'G'},
      {"isn", 1, 0, 'n'},
      {"count", 1, 0, 'c'},
      {"log", 0, 0, 'L'},
      {"hook", 1, 0, 'H'},
      {"disable-checksum", 0, 0, 'K'},
      {"timeout", 1, 0, 'T'},
      {"simulate", 0, 0, 'Q'},
      {"reconnect", 0, 0, 'R'},
      {"rcount", 1, 0, 'C'}
   };
   
   while((c = getopt_long(argc, argv, "r:c:F:t:p:S:D:E:G:LH:KT:QRC:", lops, &oi)) != -1) {
      switch(c) {
         case 'r':
            if(!strncmp(optarg, "client", 6))
               role = ROLE_CLIENT;
            if(!strncmp(optarg, "server", 6))
               role = ROLE_SERVER;

            break;
         case 'F':
            pd_file = strdup(optarg);
            break;

         case 't':
            target_host = inet_addr(optarg);
            break;

         case 'p':
            target_port = atoi(optarg);
            break;

         case 'S':
            src_host = inet_addr(optarg);
            break;

         case 'D':
            dst_host = inet_addr(optarg);
            break;

         case 'E':
            src_port = atoi(optarg);
            break;

         case 'G':
            dst_port = atoi(optarg);
            break;

         case 'n':
            //isn = strtoul(optarg, NULL, 0);
            break;

         case 'c':
            replay_count = strtoul(optarg, NULL, 0);
            break;

         case 'L':
            enable_log = 1;
            break;

         case 'H':
            w_hook_set_file(optarg);
            break;

         case 'K':
            nids_no_cksum = 1;
            break;

         case 'T':
            sock_timeout_ms = atoi(optarg);
            break;

         case 'Q':
            sock_simulate = 1;
            break;

         case 'R':
            sock_reconn = 1;
            break;

         case 'C':
            sock_reconn_count = atoi(optarg);
            break;

         default:
            help();
            break;
      }
   }

   if(!(role && pd_file && target_port))
      help();
}

static void w_tcp_callback_1(struct tcp_stream *a_tcp, void **p)
{
   static int count = 1;
   struct tcp_session *ts;

   if(a_tcp->nids_state != NIDS_JUST_EST)
      return;

   if(count > max_tcp_streams)
      cfatal("Max TCP stream limit reached");

   cmsg_up("Loading TCP sessions from pcap dump.. count:%d", count);
   ts = (struct tcp_session*) malloc(sizeof(*ts));
   assert(ts != NULL);
   
   ts->tcp.source = a_tcp->addr.source;
   ts->tcp.dest = a_tcp->addr.dest;
   ts->tcp.saddr = a_tcp->addr.saddr;
   ts->tcp.daddr = a_tcp->addr.daddr;
   ts->server_fd_seq = a_tcp->server.first_data_seq;
   ts->client_fd_seq = a_tcp->client.first_data_seq;

   LIST_INSERT_HEAD(&tcp_sessions, ts, link);
   count++;
}

static void w_tcp_callback_2(struct tcp_stream *a_tcp, void **p)
{
   struct half_stream *hlf;
   uint8_t direction;
   static int old_server_data;
   static int old_client_data;

	if(a_tcp->nids_state == NIDS_JUST_EST) {
		/* We are interested only in the selected session */
		if((src_host == a_tcp->addr.saddr) &&
			(dst_host == a_tcp->addr.daddr) &&
			(src_port == a_tcp->addr.source) &&
			(dst_port == a_tcp->addr.dest) &&
         (client_fd_seq == a_tcp->client.first_data_seq) &&
         (server_fd_seq == a_tcp->server.first_data_seq)) {
			
         a_tcp->server.collect++;
			a_tcp->client.collect++;

         old_server_data = 0;
         old_client_data = 0;

         memset(&server_data, 0x00, sizeof(server_data));
         memset(&client_data, 0x00, sizeof(client_data));
        
         //cmsg("Session starting..");
         w_event_session_start();
         return;
      }
   }

   if(a_tcp->nids_state == NIDS_JUST_EST)
      return; /* Ignore further sessions */

   if((a_tcp->nids_state == NIDS_CLOSE) ||
      (a_tcp->nids_state == NIDS_RESET) ||
      (a_tcp->nids_state == NIDS_TIMED_OUT)) {

      return;
   }

   if(a_tcp->nids_state == NIDS_EXITING) {
      //cmsg("Session closing..");
      w_event_session_stop();

      return;  
   }

   if(a_tcp->nids_state != NIDS_DATA)
      cfatal("Unexpected nids state (%d)", a_tcp->nids_state);

   if(a_tcp->client.count_new) {
      hlf = &a_tcp->client;
      /*
       * if role == server
       *    we_need_to_send()
       * else
       *    we_have_received()
       * end
       */
      direction = REPLAY_SERVER_TO_CLIENT;
      client_data.data = a_tcp->client.data;
      client_data.len = a_tcp->client.count;
      client_data.new_data = a_tcp->client.data + a_tcp->client.count - a_tcp->client.count_new;
      client_data.newlen = a_tcp->client.count_new;
   }
   else {
      hlf = &a_tcp->server;
      /*
       * if role == server
       *    we_have_received()
       * else
       *    we_have_to_send()
       * end
       */
      direction = REPLAY_CLIENT_TO_SERVER;
      server_data.data = a_tcp->server.data;
      server_data.len = a_tcp->server.count;
      server_data.new_data = a_tcp->server.data + a_tcp->server.count - a_tcp->server.count_new;
      server_data.newlen = a_tcp->server.count_new;
   }

   nids_discard(a_tcp, 0); /* We don't want discard of data */
   w_event_session_data(direction);
}

static void w_get_session_idents_from_user()
{
   struct tcp_session *ts;
   struct sockaddr_in in1;
   struct sockaddr_in in2;
   char *p1, *p2;
   int c = 0;
   int n;
   
   cmsg_raw("       \t%16s \t %6s \t %16s \t %6s \t %6s \t %6s\n",
            "SHOST",
            "SPORT",
            "DHOST",
            "DPORT",
            "CDSEQ",
            "SDSEQ");
   LIST_FOREACH(ts, &tcp_sessions, link) {
      cmsg_raw("[%4d] \t", c + 1);

      in1.sin_addr.s_addr = ts->tcp.saddr;
      in2.sin_addr.s_addr = ts->tcp.daddr;

      p1 = (char*) strdup((char*)inet_ntoa(in1.sin_addr));
      p2 = (char*) strdup((char*)inet_ntoa(in2.sin_addr));

      cmsg_raw("%16s \t %6d \t %16s \t %6d \t 0x%6x \t 0x%6x\n",
               p1,
               ts->tcp.source,
               p2,
               ts->tcp.dest,
               ts->client_fd_seq,
               ts->server_fd_seq);

      free(p1);
      free(p2);
      c++;

      if(!(c % 30)) {   /* TODO: get console size using ioctl() */
         cmsg_raw("Press return key to continue..");
         getchar();
      }
   }
   
   cmsg_nl();
   cmsg_raw("Enter session no. to replay: ");
   scanf("%d", &n);

   if((n < 0) || (n > c))
      cfatal("invalid session selected");

   c = 0;
   LIST_FOREACH(ts, &tcp_sessions, link) {
      if((n - 1) == c) {
         src_host = ts->tcp.saddr;
         dst_host = ts->tcp.daddr;
         src_port = ts->tcp.source;
         dst_port = ts->tcp.dest;
         server_fd_seq = ts->server_fd_seq;
         client_fd_seq = ts->client_fd_seq;
         break;
      }

      c++;
   }
}

/*
 * Load all the TCP sessions on memory, list them and provide the user choice to
 * select one
 *
 */
static void w_get_session_idents()
{
   nids_params.device = NULL;
   nids_params.filename = pd_file;

   if(!nids_init())
      cfatal("failed to initialized nids (%s)", nids_errbuf);

   if(nids_no_cksum) {
      /* 
       * sometimes checksum of certain packets in sniffed session might be
       * wrong, this is due to TCP checksum offload to hardware
       */
      struct nids_chksum_ctl ctl;

      cmsg("Disabling NIDS checksum calculation");

      ctl.netaddr = inet_addr("0.0.0.0");
      ctl.mask = inet_addr("0.0.0.0");
      ctl.action = NIDS_DONT_CHKSUM;

      nids_register_chksum_ctl(&ctl, 1);
   }
   
   LIST_INIT(&tcp_sessions);
   nids_register_tcp(w_tcp_callback_1);
   nids_run();
   cmsg_nl();
   nids_exit();

   w_get_session_idents_from_user();

   return;
}

static void setup_client_role()
{
   struct sockaddr_in sin;
   int lc;
   int cf;
      
   if(sock_simulate) {
      cmsg("Simulating connect to target host..");
   } else {
      cmsg("Connecting to target host..");

      csock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      assert(csock != -1);
      
      lc = 0;
      cf = 0;  /* connect success flag */
      do {
         sin.sin_addr.s_addr = target_host;
         sin.sin_port = htons(target_port);
         sin.sin_family = AF_INET;

         if(connect(csock, (struct sockaddr*) &sin, sizeof(sin))) {
            w_hook_event_error(&whd, ERROR_CONNECT_FAILED);

            if(sock_reconn) {
               cmsg("Sleeping %d seconds before reconnect attempt.. (C: %d, M: %d)", sock_reconn_wait, lc + 1, sock_reconn_count);
               sleep(sock_reconn_wait);
            }
         }
         else {
            cf = 1;
            break;
         }

      } while((sock_reconn) && (sock_reconn_count > ++lc));

      if(!cf)
         cfatal("Failed to connect");
   }
}

static void setup_server_role()
{
   struct sockaddr_in sin;
   struct sockaddr_in cin;
   int size;
   int i;

   if(sock_simulate) {
      cmsg("Simulating accept from remote client");

   } else {
      bsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      assert(bsock != -1);

      sin.sin_addr.s_addr = INADDR_ANY;
      sin.sin_port = htons(target_port);
      sin.sin_family = AF_INET;

      cmsg("Listening on port %d", target_port);
      i = 1;
      setsockopt(bsock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)); /* Security Risk */
      if(bind(bsock, (struct sockaddr*)&sin, sizeof(sin)))
         cfatal("failed to bind socket");

      listen(bsock, 100);
      size = sizeof(cin);

      csock = accept(bsock, (struct sockaddr*)&cin, &size);

      cmsg("Got connection from %s:%d",
         inet_ntoa(cin.sin_addr), ntohs(cin.sin_port));
   }
}

/*
 * Initialize network sockets based on client/server role selection
 */
static void w_init_role()
{
   if(sock_simulate)
      cmsg("Running in simulation mode");

   if(role == ROLE_CLIENT)
      setup_client_role();
   else if(role == ROLE_SERVER)
      setup_server_role();
   else
      cfatal("invalid role");
}

/*
 * De-initialize network sockets
 */
static void w_deinit_role()
{
   if(sock_simulate)
      return;

   shutdown(csock, SHUT_RDWR);
   close(csock);

   if(role == ROLE_SERVER) {
      shutdown(bsock, SHUT_RDWR);
      close(bsock);
   }
}

/*
 * Called from nids loop to mark start of the session
 *
 * Ideally here we should tell the hooks that the session is starting
 */
static void w_event_session_start()
{
   if(session_started)
      cmsg("WARN: Session already started..");

   cmsg("Session start event raised");
   session_started = 1;
   server_data_count = 0;
   client_data_count = 0;
   
   w_hook_event_start(&whd);
}

/*
 * Called from nids loop to mark stop of the session
 *
 * Ideally here we should tell the hooks that the session has stopped
 */
static void w_event_session_stop()
{
   if(!session_started)
      cmsg("WARN: Session already stopped..");

   cmsg("Session stop event raised");
   session_started = 0;
   
   w_hook_event_stop(&whd);
}

/*
 * Send packet data to socket
 */
static void w_replay_send(uint8_t direction)
{
   int ret;
   char *buf = NULL;
   size_t len;
   fd_set fds;
   struct timeval tv;


   if(role == ROLE_CLIENT) {
      len = server_data.newlen;
      buf = malloc(len + 1);
      assert(buf != NULL);

      memcpy(buf, server_data.new_data, server_data.newlen);
   }
   else {
      len = client_data.newlen;
      buf = malloc(len + 1);
      assert(buf != NULL);

      memcpy(buf, client_data.new_data, client_data.newlen);
   }
  
   w_hook_event_data(&whd, direction, &buf, &len);
   
   w_log_printf(">>>>\n");
   w_log_write(buf, len);
   
   ret = len;  /* default when simulating */

   if(!sock_simulate)
      ret = send(csock, buf, len, 0);

   if(ret < 0) {
      w_hook_event_error(&whd, ERROR_SEND_FAILED);
   } else {
      if(role == ROLE_CLIENT)
         server_data_count += ret;
      else
         client_data_count += ret;
   }

   if(buf)
      free(buf);
}

/*
 * Receive data from socket
 */
static void w_replay_recv(uint8_t direction)
{
   int ret;
   char *buf = NULL;
   size_t len;
   fd_set fds;
   struct timeval tv;
   
   if(role == ROLE_CLIENT) {
      len = client_data.newlen;
      buf = malloc(len + 1);
      assert(buf != NULL);

      memcpy(buf, client_data.new_data, len);   /* default for simulation */
   } else {
      len = server_data.newlen;
      buf = malloc(len + 1);
      assert(buf != NULL);

      memcpy(buf, server_data.new_data, len);   /* default for simulation */
   }


   ret = 1; /* default when simulating */

   if(!sock_simulate) {
      FD_ZERO(&fds);
      FD_SET(csock, &fds);
      tv.tv_sec = 0;
      tv.tv_usec = sock_timeout_ms;

      ret = select(csock + 1, &fds, NULL, NULL, &tv);
   }

   if(ret > 0) {
      ret = len; /* default when simulating */

      if(!sock_simulate)
         ret = recv(csock, buf, len , 0);

      if(ret < 0) {
         w_hook_event_error(&whd, ERROR_RECV_FAILED);
      } else {
         if(role == ROLE_CLIENT)
            client_data_count += ret;
         else
            server_data_count += ret;

         w_log_printf("<<<<\n");
         w_log_write(buf, ret);
   
         w_hook_event_data(&whd, direction, &buf, &ret);
      }
   }
   else {
      w_hook_event_error(&whd, ERROR_TIMEOUT);
   }

   if(buf)
      free(buf);
}

/*
 * Called from nids loop to mark session data
 *
 * Here we should:
 *
 * 1) Call the hook functions
 * 2) Replay the data to server/client
 */
static void w_event_session_data(uint8_t direction)
{
   if(!session_started)
      cmsg("WARN: Session not started..");

   switch(role) {
      case ROLE_CLIENT:
         if(direction == REPLAY_SERVER_TO_CLIENT) {
            w_replay_recv(direction);
         } else {
            w_replay_send(direction);
         }
         break;
      case ROLE_SERVER:
         if(direction == REPLAY_SERVER_TO_CLIENT) {
            w_replay_send(direction);
         } else {
            w_replay_recv(direction);
         }

         break;
   }

   cmsg_up("Run Count: %d Server data: %d Client data: %d",
                  run_count + 1,
                  server_data_count, 
                  client_data_count);
   //sleep(1);
   return;
}

/*
 * Start the replay process:
 *
 * Goes into nids_run() loop
 */
static void w_start_replay()
{
   nids_params.device = NULL;
   nids_params.filename = pd_file;
  
   signal(SIGPIPE, SIG_IGN);  /* TODO: Send event to hooks */
   signal(SIGINT, sigint_handler1);
   /* TODO: use sigaction(..) to save Ruby's sigsegv handler for later 
    * restore */
   //signal(SIGSEGV, segv_handler1);

   if(!nids_init())
      cfatal("failed to initialized nids (%s)", nids_errbuf);

   if(nids_no_cksum) {
      /* 
       * sometimes checksum of certain packets in sniffed session might be
       * wrong, this is due to TCP checksum offload to hardware
       */
      struct nids_chksum_ctl ctl;

      cmsg("Disabling NIDS checksum calculation");

      ctl.netaddr = inet_addr("0.0.0.0");
      ctl.mask = inet_addr("0.0.0.0");
      ctl.action = NIDS_DONT_CHKSUM;

      nids_register_chksum_ctl(&ctl, 1);
   }

   nids_register_tcp(w_tcp_callback_2);
   nids_run();
   cmsg_nl();
   nids_exit();

   if(session_started)
      w_event_session_stop();

   //signal(SIGSEGV, SIG_DFL);
}

static void w_stop_replay()
{
   nids_unregister_tcp(w_tcp_callback_2);
   nids_exit();
}

/*
 * Initialize libnids
 */
static void w_nids_init()
{
   if(!pd_file)
      cfatal("pcap dump file not specified");

   if(!(src_host && src_port && dst_host && dst_port))
      w_get_session_idents();

   return;
}

int main(int argc, char **argv)
{
   conf_init();
   conf_get_cmdline(argc, argv);

   if(enable_log)
      w_log_init();

#ifdef DEBUG
//   debug_init();
#endif
   
   w_nids_init();
   w_hooks_init();

   // debug
   signal(SIGSEGV, SIG_DFL);

   while(run_count < replay_count) {
      /* Setup hook desc */
      whd.host = target_host;
      whd.port = target_port;
      whd.role = role;
      whd.run_count = run_count;
      whd.p = NULL;

      w_init_role(); /* blocks here when in server role */
      w_start_replay();
      w_stop_replay();
      w_deinit_role();

      run_count++;
   }

   return 0;
}
