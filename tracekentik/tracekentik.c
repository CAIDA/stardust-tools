/*
 * This software is Copyright © 2020 The Regents of the University of
 * California. All Rights Reserved. Permission to copy, modify, and distribute
 * this software and its documentation for educational, research and non-profit
 * purposes, without fee, and without a written agreement is hereby granted,
 * provided that the above copyright notice, this paragraph and the following
 * three paragraphs appear in all copies. Permission to make commercial use of
 * this software may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * "as is", without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */


/**
 *  tracekentik: simple tool that uses libtrace to sample packets and send them
 *               to the kentik platform (via their "darknet" proxy).
 *
 *  Author: Alistair King
 */

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrace_parallel.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "darknet.pb-c.h"

char *filter_expr;
struct libtrace_filter_t *filter;
int threadcount = 0;
uint64_t samplerate = 10;
int bufferlen = 10;

char *uri;
libtrace_t *trace = NULL;

struct sockaddr_in proxyaddr;

static void cleanup_signal(int signal UNUSED)
{
  if (trace) {
    trace_pstop(trace);
  }
}

typedef struct threadlocal {

  uint64_t pkt_cnt; // # pkts since last sample
  uint64_t sample_cnt; // # pkts that have been sampled

  Darknet__DarknetFlows pbflows;
  int cur_flow;
  uint8_t *buffer;
  size_t buffersize;

  int fd;

} threadlocal_t;

static void free_tls(threadlocal_t *tls) {
  if (tls) {
    if (tls->fd != 0) {
      close(tls->fd);
    }
    for (int i = 0; i < tls->pbflows.n_flow; i++) {
      darknet__darknet_flow__free_unpacked(tls->pbflows.flow[i], NULL);
      tls->pbflows.flow[i] = NULL;
    }
    tls->pbflows.n_flow = 0;
    free(tls->pbflows.flow);
    tls->pbflows.flow = NULL;
  }
  free(tls);
}

#define CURFLOW (tls->pbflows.flow[tls->cur_flow])

#define PB_HAS(field)                                                          \
  do {                                                                         \
    (CURFLOW)->has_##field = 1;                                                \
  } while (0)

#define PB_SET(field, value)                                                   \
  do {                                                                         \
    (CURFLOW)->field = value;                                                  \
  } while (0)

static void *cb_starting(libtrace_t *trace UNUSED,
                         libtrace_thread_t *t UNUSED,
                         void *global UNUSED)
{
  threadlocal_t *tls = NULL;
  if ((tls = calloc(1, sizeof(threadlocal_t))) == NULL) {
    goto starterr;
  }

  int tid = trace_get_perpkt_thread_id(t);

  // allocate protobufs buffer
  darknet__darknet_flows__init(&tls->pbflows);
  tls->pbflows.n_flow = bufferlen;
  tls->pbflows.flow = calloc(1, sizeof(Darknet__DarknetFlow*) * tls->pbflows.n_flow);
  for (int i = 0; i < tls->pbflows.n_flow; i++) {
    tls->pbflows.flow[i] = calloc(1, sizeof(Darknet__DarknetFlow));
    darknet__darknet_flow__init(tls->pbflows.flow[i]);
    tls->cur_flow = i;
    // enable all the always-used fields
    PB_HAS(timestamp);
    PB_HAS(in_bytes);
    PB_HAS(in_pkts);
    PB_HAS(ipv4_dst_addr);
    PB_HAS(ipv4_src_addr);
    PB_HAS(l4_dst_port);
    PB_HAS(l4_src_port);
    PB_HAS(protocol);
    PB_HAS(sample_rate);
    PB_HAS(packet_id);
    PB_HAS(device_id);
    // set fields that are constant per-thread
    PB_SET(sample_rate, samplerate);
    PB_SET(device_id, tid);
  }
  tls->cur_flow = 0;

  // create UDP tx socket
  if ((tls->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    perror("Socket creation failed");
    goto starterr;
  }
  // bind to a loopback address based on thread ID
  struct sockaddr_in srcaddr;
  srcaddr.sin_family = AF_INET;
  srcaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK+tid);
  srcaddr.sin_port = 0; // any port
  if (bind(tls->fd, (struct sockaddr*)&srcaddr, sizeof(srcaddr)) != 0) {
    perror("Bind failed");
    goto starterr;
  }

  return tls;

starterr:
  free_tls(tls);
  return NULL;
}

static int pack_and_tx(threadlocal_t *tls) {
  assert(tls->buffer == NULL);
  // TODO: don't malloc/free this every time...
  tls->buffersize = darknet__darknet_flows__get_packed_size(&tls->pbflows);
  // allocate buffer for packed data
  tls->buffer = malloc(tls->buffersize);

  size_t packedsize = darknet__darknet_flows__pack(&tls->pbflows, tls->buffer);
  assert(packedsize == tls->buffersize);

  // TODO: use sendmsg instead
  sendto(tls->fd, tls->buffer, tls->buffersize, 0, (struct sockaddr *)&proxyaddr,
         sizeof(proxyaddr));
  // XXX fall through and thus drop this buffer
  // TODO: is there something better to do here?

  free(tls->buffer);
  tls->buffer = NULL;
  tls->buffersize = 0;
  tls->cur_flow = 0;
  return 0;
}

static libtrace_packet_t *cb_packet(libtrace_t *trace,
                                    libtrace_thread_t *t,
                                    void *global UNUSED,
                                    void *td,
                                    libtrace_packet_t *packet) {

  threadlocal_t *tls = (threadlocal_t *)td;

  if (IS_LIBTRACE_META_PACKET(packet)) {
    goto skip;
  }

  if (tls->pkt_cnt % samplerate == 0) {
    // fprintf(stderr, "DEBUG: TID: %d, sample: %"PRIu64"\n", tid, tls->sample_cnt);
    tls->sample_cnt++;
  } else {
    // ignore this packet
    goto unwanted;
  }

  // this is a packet we care about, extract details, and buffer it up
  PB_SET(packet_id, tls->sample_cnt);
  PB_SET(timestamp, trace_get_erf_timestamp(packet));

  uint16_t ethertype;
  uint32_t rem;
  libtrace_ip_t *ip_hdr = (libtrace_ip_t *)(trace_get_layer3(packet, &ethertype, &rem));
  if (ip_hdr == NULL || ethertype != TRACE_ETHERTYPE_IP ||
      rem < sizeof(libtrace_ip_t)) {
    /* non-ipv4 packet or truncated */
    goto skip;
  }

  PB_SET(in_bytes, ntohs(ip_hdr->ip_len));
  PB_SET(in_pkts, 1);
  // XXX input_port unused
  // XXX output_port unused
  PB_SET(ipv4_dst_addr, ntohl(ip_hdr->ip_dst.s_addr));
  PB_SET(ipv4_src_addr, ntohl(ip_hdr->ip_src.s_addr));
  PB_SET(protocol, ip_hdr->ip_p);

  // XXX tls->tmpflow.ttl = ip_hdr->ip_ttl;

  void *transport = trace_get_payload_from_ip(ip_hdr, &ip_hdr->ip_p, &rem);
  if (!transport) {
    /* transport header is missing or this is an non-initial IP fragment */
    goto skip;
  }

  if (ip_hdr->ip_p == TRACE_IPPROTO_ICMP && rem >= 2) {
    /* ICMP doesn't have ports, but we are interested in the type and
     * code, so why not reuse the space in the tag structure :) */
    libtrace_icmp_t *icmp = (libtrace_icmp_t *)transport;
    PB_SET(l4_src_port, icmp->type);
    PB_SET(l4_dst_port, icmp->code);
  } else if ((ip_hdr->ip_p == TRACE_IPPROTO_TCP ||
              ip_hdr->ip_p == TRACE_IPPROTO_UDP) &&
             rem >= 4) {
    PB_SET(l4_src_port, ntohs(*((uint16_t *)transport)));
    PB_SET(l4_dst_port, ntohs(*(((uint16_t *)transport) + 1)));

    // TCP flags
    if (ip_hdr->ip_p == TRACE_IPPROTO_TCP && rem >= sizeof(libtrace_tcp_t)) {
      /* Quicker to just read the whole byte direct from the packet,
       * rather than dealing with the individual flags.
       */
      PB_HAS(tcp_flags);
      PB_SET(tcp_flags, *((uint8_t *)transport) + 13);
    } else {
      (CURFLOW)->has_tcp_flags = 0;
    }
  }

  if (++tls->cur_flow == bufferlen &&
      pack_and_tx(tls) != 0) {
    // TODO: it's UDP, so just keep blasting away?
  }
  assert(tls->cur_flow < bufferlen);

unwanted:
  tls->pkt_cnt++;
skip: // don't count the packet
  return packet;
}

static void cb_stopping(libtrace_t *trace, libtrace_thread_t *t,
                        void *global UNUSED, void *td) {

  threadlocal_t *tls = (threadlocal_t *)td;
  free_tls(tls);
}

static int run_trace() {
  fprintf(stderr, "Consuming from %s\n", uri);

  libtrace_callback_set_t *pktcbs;

  trace = trace_create(uri);

  if (trace_is_err(trace)) {
    trace_perror(trace, "Failed to create trace");
    trace_destroy(trace);
    return -1;
  }

  pktcbs = trace_create_callback_set();
  trace_set_starting_cb(pktcbs, cb_starting);
  trace_set_stopping_cb(pktcbs, cb_stopping);
  trace_set_packet_cb(pktcbs, cb_packet);

  if (threadcount != 0) {
    trace_set_perpkt_threads(trace, threadcount);
  }

  /* Start the trace as a parallel trace */
  if (trace_pstart(trace, NULL, pktcbs, NULL) == -1) {
    trace_perror(trace, "Failed to start trace");
    trace_destroy(trace);
    trace_destroy_callback_set(pktcbs);
    return -1;
  }

  /* Wait for all threads to stop */
  trace_join(trace);

  if (trace_is_err(trace)) {
    trace_perror(trace,"%s", uri);
  }

  trace_destroy(trace);
  trace_destroy_callback_set(pktcbs);
  return 0;
}

static void usage(char *cmd) {
  fprintf(
      stderr,
      "Usage: %s [-h|--help] [--samplerate|-s npkts] [--threads|-t threads]\n"
      "[--filter|-f bpf] [--bufferlen|-b nflows] libtraceuri "
      "kentikproxy:port\n",
      cmd);
}

int main(int argc, char *argv[]) {
  struct sigaction sigact;
  int rc = -1;

  while (1) {
    int option_index;
    struct option long_options[] = {
        {"bufferlen", 1, 0, 'b'},     //
        {"filter", 1, 0, 'f'},     //
        {"help", 0, 0, 'h'},       //
        {"threads", 1, 0, 't'},    //
        {"samplerate", 1, 0, 's'}, //
        {NULL, 0, 0, 0},           //
    };

    int c = getopt_long(argc, argv, "b:f:hs:t:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
    case 'b':
      bufferlen = atoi(optarg);
      break;
    case 'f':
      if (filter) {
        fprintf(stderr, "Only one filter can be specified\n");
        usage(argv[0]);
        goto cleanup;
      }
      filter_expr = strdup(optarg);
      filter = trace_create_filter(optarg);
      break;
    case 's':
      samplerate = atoi(optarg);
      break;
    case 'h':
      usage(argv[0]);
      goto cleanup;
    case 't':
      threadcount = atoi(optarg);
      if (threadcount <= 0)
        threadcount = 1;
      break;
    default:
      fprintf(stderr, "Unknown option: %c\n", c);
      usage(argv[0]);
      goto cleanup;
    }
  }

  if (argc == 0 || argc - optind != 2) {
    usage(argv[0]);
    return -1;
  }

  uri = argv[optind];
  char *proxyhost = strdup(argv[optind+1]);
  char *portstr = NULL;
  if ((portstr = strchr(proxyhost, ':')) == NULL) {
    fprintf(stderr, "ERROR: proxy port missing\n");
    usage(argv[0]);
    goto cleanup;
  }
  *portstr++ = '\0';
  uint16_t proxyport = atoi(portstr);
  fprintf(stderr, "INFO: Publishing flows to %s:%"PRIu16"\n", proxyhost, proxyport);

  memset(&proxyaddr, 0, sizeof(proxyaddr));
  proxyaddr.sin_family = AF_INET;
  proxyaddr.sin_port = htons(proxyport);

  struct hostent *hp = gethostbyname(proxyhost);
  if (!hp) {
    fprintf(stderr, "ERROR: could not obtain address of %s\n", proxyhost);
    return 0;
  }
  memcpy((void *)&proxyaddr.sin_addr, hp->h_addr_list[0], hp->h_length);

  free(proxyhost);

  sigact.sa_handler = cleanup_signal;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = SA_RESTART;

  sigaction(SIGINT, &sigact, NULL);
  sigaction(SIGTERM, &sigact, NULL);

  rc = run_trace();

cleanup:
  return rc;
}
