/*
 * This software is Copyright © 2019 The Regents of the University of
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
 *  ft_prefixgrep: extract flowtuples where either the source or destination IP
 *                 address falls within a given IP prefix
 *
 *  Author: Shane Alcock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <wandio.h>
#include <flowtuple.h>

/* This is just a quick program that I hacked up to help Alberto quickly find
 * flowtuples relating to a particular prefix that he was interested in.
 *
 * Note that this code will only work with the legacy "pre-STARDUST" flowtuple
 * file format -- hopefully Spark will more or less replace this sort of
 * program for dealing with the new flowtuple files.
 *
 * Uses Mark Weiman's libflowtuple to read and parse the legacy flowtuple
 * records. A copy can be found here:
 *     https://github.com/Merit-Research/libflowtuple
 */

/** Expected input: a single flowtuple file and a prefix, as command line
 *  arguments.
 *
 *  Expected output: a CSV file where each line contains a flowtuple that
 *  matched the given prefix.
 *
 *  Combine with gnu parallel (or similar) to process multiple flowtuple
 *  files in parallel.
 *
 *  CSV format is:
 *      interval timestamp, source IP, dest IP, source port, dest port,
 *      protocol, TTL, TCP Flags, IP length, Packet Count
 */

/** Global state for the analysis */
struct ft_grep_state {

    /** Name of the file to write the output to */
    char *outfilename;
    /** Libwandio handle for the output file */
    iow_t *outhandle;

    /** The IP address portion of the prefix */
    uint32_t prefixbits;
    /** The bitmask portion of the prefix */
    uint32_t prefixmask;
    /** Flag indicating whether to try to match the source address, dest
     *  address, or either */
    uint8_t whichaddrs;

    /** The timestamp of the most recent interval record */
    uint32_t interval_ts;

};

/** Per-record callback function for flowtuple_loop.
 *
 */
static void process_record(flowtuple_record_t *record, void *args) {

    struct ft_grep_state *state = (struct ft_grep_state *)args;
    flowtuple_record_type_t type = flowtuple_record_get_type(record);
    flowtuple_data_t *ftdata;
    flowtuple_interval_t *interval;
    uint8_t towrite = 0;
    uint32_t ipaddr;
    char ft_string[2048];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    /* If this is an interval record, we need to save the timestamp so
     * that we can correctly label any matched flows with the interval
     * that they belonged to.
     */
    if (type == FLOWTUPLE_RECORD_TYPE_INTERVAL) {
        interval = flowtuple_record_get_interval(record);
        if (interval == NULL) {
            return;
        }
        state->interval_ts = ntohl(flowtuple_interval_get_time(interval));
    }

    /* Otherwise, only data records matter to us */
    if (type != FLOWTUPLE_RECORD_TYPE_FLOWTUPLE_DATA) {
        return;
    }

    ftdata = flowtuple_record_get_data(record);
    if (!ftdata) {
        return;
    }

    /** If whichaddrs is 2, then it's a destination only check */
    if (state->whichaddrs != 2) {
        ipaddr = flowtuple_data_get_src_ip(ftdata);

        if ((ipaddr & state->prefixmask) == state->prefixbits) {
            towrite = 1;
        }
    }

    /** If whichaddrs is 1, then it's a source only check */
    if (state->whichaddrs != 1) {
        ipaddr = flowtuple_data_get_dest_ip(ftdata);

        if ((ipaddr & state->prefixmask) == state->prefixbits) {
            towrite = 1;
        }
    }

    /* If the addresses didn't match our prefix, then move on. */
    if (!towrite || state->outhandle == NULL) {
        return;
    }

    /* Write matched flowtuple to the output file */
    *(uint32_t *)(src_ip) = flowtuple_data_get_src_ip(ftdata);
    *(uint32_t *)(dst_ip) = flowtuple_data_get_dest_ip(ftdata);

    /* Account for flowtuple files that might be saving space by
     * not writing the "static" first octet because the network
     * was a /8.
     * In this case, I've assumed that the network was 44/8
     * (i.e. the UCSD telescope).
     */
    if (flowtuple_data_is_slash_eight(ftdata)) {
        dst_ip[0] = 44;
    }

    /* Construct the CSV output line for the matched flowtuple */
    snprintf(ft_string, 2048,
            "%u,%u.%u.%u.%u,%u.%u.%u.%u,%u,%u,%u,%u,0x%02x,%u,%u\n",
            state->interval_ts,
            src_ip[0], src_ip[1], src_ip[2], src_ip[3],
            dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
            ntohs(flowtuple_data_get_src_port(ftdata)),
            ntohs(flowtuple_data_get_dest_port(ftdata)),
            flowtuple_data_get_protocol(ftdata),
            flowtuple_data_get_ttl(ftdata),
            flowtuple_data_get_tcp_flags(ftdata),
            ntohs(flowtuple_data_get_ip_len(ftdata)),
            ntohl(flowtuple_data_get_packet_count(ftdata)));

    if (wandio_wwrite(state->outhandle, ft_string, strlen(ft_string)) < 0) {
        fprintf(stderr, "Error while writing flowtuple to output file\n");
        wandio_wdestroy(state->outhandle);
        state->outhandle = NULL;
    }

}

/** Takes a string describing a prefix in the format A.B.C.D/m and
 *  generates a 32 bit prefix and a 32 bit mask to assist with matching
 *  IPv4 addresses against that prefix.
 */
static void parse_prefix(char *pfxstring, uint32_t *mask, uint32_t *pbits) {

    /* Adapted from libpatricia's ascii2prefix function */
    int maxbitlen = 32, bitlen;
    char *cp;
    char localsave[32];
    struct in_addr result;
    uint32_t startmask = 0xFFFFFFFF;

    if ((cp = strchr(pfxstring, '/')) != NULL) {
        bitlen = atol(cp + 1);

        memcpy(localsave, pfxstring, cp - pfxstring);
        localsave[cp - pfxstring] = '\0';

        if (bitlen > maxbitlen) {
            bitlen = maxbitlen;
        }
    } else {
        memset(localsave, 0, 32);
        bitlen = maxbitlen;
        strncpy(localsave, pfxstring, 31);
    }

    if (inet_pton(AF_INET, localsave, (void *)&result) == 1) {
        *mask = htonl((startmask << (32 - bitlen)));
        *pbits = (result.s_addr & (*mask));
    } else {
        fprintf(stderr, "%s is not a valid IPv4 prefix\n", pfxstring);
    }
}

int main(int argc, char *argv[]) {
    uint8_t whichcheck = 0;     // 0 == both, 1 == source, 2 == dest
    uint32_t prefixmask = 0;
    uint32_t prefixbits = 0;
    flowtuple_errno_t err;

    char *ftfileloc = NULL;
    char *outputfile = NULL;
    flowtuple_handle_t *h = NULL;
    struct ft_grep_state state;

    while (1) {
        int option_index;
        int opt;
        struct option long_options[] = {
            { "checksource",        0, 0, 's' },
            { "checkdest",          0, 0, 'd' },
            { "datafiles",          1, 0, 'f' },
            { "prefix",             1, 0, 'p' },
            { "outputfile",         1, 0, 'o' },
            { NULL,                 0, 0, 0}
        };

        opt = getopt_long(argc, argv, "sdf:p:o:", long_options, &option_index);
        if (opt == -1) {
            break;
        }

        switch(opt) {
            case 's':
                whichcheck = 1;
                break;
            case 'd':
                whichcheck = 2;
                break;
            case 'o':
                outputfile = optarg;
                break;
            case 'f':
                ftfileloc = optarg;
                break;
            case 'p':
                /* Determine prefix and mask */
                parse_prefix(optarg, &prefixmask, &prefixbits);
                break;
        }
    }

    if (outputfile == NULL) {
        fprintf(stderr, "No output file location given using -o, unable to run.\n");
        return -1;
    }

    if (ftfileloc == NULL) {
        fprintf(stderr, "No location given for flowtuple files using -f, unable to run.\n");
        return -1;
    }

    if (prefixbits == 0) {
        fprintf(stderr, "No valid prefix given using -p, unable to run.\n");
        return -1;
    }

    state.outfilename = outputfile;
    state.outhandle = wandio_wcreate(outputfile, WANDIO_COMPRESS_NONE, 0,
            O_CREAT);

    if (state.outhandle == NULL) {
        fprintf(stderr, "Failed to create output handle -- exiting.\n");
        return -1;
    }

    state.prefixbits = prefixbits;
    state.prefixmask = prefixmask;
    state.whichaddrs = whichcheck;
    /** Default value of 101 should never appear in output */
    state.interval_ts = 101;

    /* Basic libflowtuple open, read, close pipeline */
    h = flowtuple_initialize(ftfileloc, &err);

    flowtuple_loop(h, -1, process_record, (void *)&state);

    err = err == FLOWTUPLE_ERR_OK ? flowtuple_errno(h) : err;
    if (err != FLOWTUPLE_ERR_OK) {
        fprintf(stderr, "ERROR: %s\n", flowtuple_strerr(err));
    }

    flowtuple_release(h);

    if (state.outhandle) {
        wandio_wdestroy(state.outhandle);
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
