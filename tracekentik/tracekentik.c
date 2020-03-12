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
 *               to the kentik platform using msgpack.
 *
 *  Author: Alistair King
 */

#include <getopt.h>
#include <inttypes.h>
#include <libtrace_parallel.h>
#include <msgpack.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

char *filter_expr;
struct libtrace_filter_t *filter;
int threadcount = 0;
uint64_t samplerate = 10;

char *uri;
libtrace_t *trace = NULL;

struct sockaddr_in proxyaddr;

static void cleanup_signal(int signal UNUSED)
{
  if (trace) {
    trace_pstop(trace);
  }
}

typedef struct flow {
  uint8_t tid; // XXX thread ID (device ID in kentik)
  uint64_t ts; // XXX timestamp (from ERF)
  uint16_t ip_len; // IP length (bytes)
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t proto;
  uint8_t ttl;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t tcp_flags;
  uint32_t pkt_cnt; // XXX
} PACKED flow_t;

typedef struct threadlocal {

  uint64_t pkt_cnt; // # pkts since last sample
  uint64_t sample_cnt; // # pkts that have been sampled

  flow_t tmpflow;

  int fd;

} threadlocal_t;

static void *cb_starting(libtrace_t *trace UNUSED,
                         libtrace_thread_t *t UNUSED,
                         void *global UNUSED)
{
  threadlocal_t *tls = calloc(1, sizeof(threadlocal_t));
  tls->tmpflow.pkt_cnt = 1;

  if ((tls->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
    perror("Socket creation failed");
    free(tls);
    return NULL;
  }

  return tls;
}

static int tx_packet(int fd, void *msg, uint64_t msglen) {
  if (sendto(fd, msg, msglen, 0, (struct sockaddr *)&proxyaddr,
             sizeof(proxyaddr)) < 0) {
    perror("UDP tx failed");
    return -1;
  }
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

  // this is a packet we care about, extract details, msgpack it and send
  tls->tmpflow.tid = trace_get_perpkt_thread_id(t);
  tls->tmpflow.ts = trace_get_erf_timestamp(packet);

  uint16_t ethertype;
  uint32_t rem;
  libtrace_ip_t *ip_hdr = (libtrace_ip_t *)(trace_get_layer3(packet, &ethertype, &rem));
  if (ip_hdr == NULL || ethertype != TRACE_ETHERTYPE_IP ||
      rem < sizeof(libtrace_ip_t)) {
    /* non-ipv4 packet or truncated */
    goto skip;
  }

  tls->tmpflow.ip_len = ntohs(ip_hdr->ip_len);
  tls->tmpflow.src_ip = ntohl(ip_hdr->ip_src.s_addr);
  tls->tmpflow.dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
  tls->tmpflow.proto = ip_hdr->ip_p;
  tls->tmpflow.ttl = ip_hdr->ip_ttl;

  void *transport = trace_get_payload_from_ip(ip_hdr, &tls->tmpflow.proto, &rem);
  if (!transport) {
    /* transport header is missing or this is an non-initial IP fragment */
    goto skip;
  }
  tls->tmpflow.src_port = 0;
  tls->tmpflow.dst_port = 0;
  tls->tmpflow.tcp_flags = 0;
  if (tls->tmpflow.proto == TRACE_IPPROTO_ICMP && rem >= 2) {
    /* ICMP doesn't have ports, but we are interested in the type and
     * code, so why not reuse the space in the tag structure :) */
    libtrace_icmp_t *icmp = (libtrace_icmp_t *)transport;
    tls->tmpflow.src_port = icmp->type;
    tls->tmpflow.dst_port = icmp->code;
  } else if ((tls->tmpflow.proto == TRACE_IPPROTO_TCP ||
              tls->tmpflow.proto == TRACE_IPPROTO_UDP) &&
             rem >= 4) {
    tls->tmpflow.src_port = ntohs(*((uint16_t *)transport));
    tls->tmpflow.dst_port = ntohs(*(((uint16_t *)transport) + 1));

    // TCP flags
    if (tls->tmpflow.proto == TRACE_IPPROTO_TCP && rem >= sizeof(libtrace_tcp_t)) {
      /* Quicker to just read the whole byte direct from the packet,
       * rather than dealing with the individual flags.
       */
      tls->tmpflow.tcp_flags = *((uint8_t *)transport) + 13;
    }
  }

  // pkts = 1

  if (tx_packet(tls->fd, &tls->tmpflow, sizeof(tls->tmpflow)) != 0) {
    // it's UDP, so just keep blasting away?
  }

unwanted:
  tls->pkt_cnt++;
skip: // don't count the packet
  return packet;
}

static void cb_stopping(libtrace_t *trace, libtrace_thread_t *t,
                        void *global UNUSED, void *td) {

  threadlocal_t *tls = (threadlocal_t *)td;
  close(tls->fd);
  free(tls);
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
  fprintf(stderr,
          "Usage: %s [-h|--help] [--samplerate|-s npkts] [--threads|-t threads]\n"
          "[--filter|-f bpf] libtraceuri kentikproxy:port\n", cmd);
}

int main(int argc, char *argv[]) {
  struct sigaction sigact;
  int rc = -1;

  while (1) {
    int option_index;
    struct option long_options[] = {
        {"filter", 1, 0, 'f'},
        {"help", 0, 0, 'h'},
        {"threads", 1, 0, 't'},
        {"samplerate", 1, 0, 's'},
        {NULL, 0, 0, 0},
    };

    int c = getopt_long(argc, argv, "f:hs:t:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
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
