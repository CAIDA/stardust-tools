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
 *  tracekflow: simple tool that uses libtrace to sample packets and send them
 *              to the kentik platform using libkflow.
 *
 *  Author: Alistair King
 */

#include <getopt.h>
#include <inttypes.h>
#include <libtrace_parallel.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *filter_expr;
struct libtrace_filter_t *filter;
int threadcount = 0;
uint64_t samplerate = 1;

libtrace_t *trace = NULL;

static void cleanup_signal(int signal UNUSED)
{
  if (trace) {
    trace_pstop(trace);
  }
}

typedef struct threadlocal {

  uint64_t pkt_cnt; // # pkts since last sample
  uint64_t sample_cnt; // # pkts that have been sampled

} threadlocal_t;

static void *cb_starting(libtrace_t *trace UNUSED,
                         libtrace_thread_t *t UNUSED,
                         void *global UNUSED)
{
  threadlocal_t *tls = calloc(0, sizeof(threadlocal_t));
  // TODO init state
  return tls;
}

static libtrace_packet_t *cb_packet(libtrace_t *trace,
                                    libtrace_thread_t *t,
                                    void *global UNUSED,
                                    void *td,
                                    libtrace_packet_t *packet) {

  threadlocal_t *tls = (threadlocal_t *)td;
  int tid = trace_get_perpkt_thread_id(t);

  if (IS_LIBTRACE_META_PACKET(packet)) {
    return packet;
  }

  if (++tls->pkt_cnt % samplerate == 0) {
    fprintf(stderr, "TID: %d, sample: %"PRIu64"\n", tid, tls->sample_cnt);
    tls->sample_cnt++;

  }

  // do something with the packet

  return packet;
}

static void cb_stopping(libtrace_t *trace, libtrace_thread_t *t,
                        void *global UNUSED, void *tls) {

  threadlocal_t *td = (threadlocal_t *)tls;
  // TODO clean up state
  free(td);
}

static int run_trace(char *uri) {
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
          "[--filter|-f bpf] libtraceuri\n", cmd);
}

int main(int argc, char *argv[]) {
  struct sigaction sigact;

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
        return -1;
      }
      filter_expr = strdup(optarg);
      filter = trace_create_filter(optarg);
      break;
    case 's':
      samplerate = atoi(optarg);
      break;
    case 'h':
      usage(argv[0]);
      return -1;
    case 't':
      threadcount = atoi(optarg);
      if (threadcount <= 0)
        threadcount = 1;
      break;
    default:
      fprintf(stderr, "Unknown option: %c\n", c);
      usage(argv[0]);
      return -1;
    }
  }

  if (argc == 0 || argc - optind != 1) {
    usage(argv[0]);
    return -1;
  }

  sigact.sa_handler = cleanup_signal;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = SA_RESTART;

  sigaction(SIGINT, &sigact, NULL);
  sigaction(SIGTERM, &sigact, NULL);

  return run_trace(argv[optind]);
}
