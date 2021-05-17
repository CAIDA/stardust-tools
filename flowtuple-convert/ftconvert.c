
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <Judy.h>
#include <sys/time.h>

#include <flowtuple.h>
#include <libcorsaro_avro.h>
#include <libcorsaro_log.h>
#include <libcorsaro_flowtuple.h>

#define MAX_QUALITY_VALUES 5

static const char NEW_FLOWTUPLE_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\":\"org.caida.corsaro\",\
  \"name\":\"flowtuple4\",\
  \"doc\":\"A Corsaro FlowTuple4 record.\",\
  \"fields\":[\
      {\"name\": \"time\", \"type\": \"long\"}, \
      {\"name\": \"src_ip\", \"type\": \"long\"}, \
      {\"name\": \"dst_net\", \"type\": \"long\"}, \
      {\"name\": \"dst_port\", \"type\": \"int\"}, \
      {\"name\": \"protocol\", \"type\": \"int\"}, \
      {\"name\": \"packet_cnt\", \"type\": \"long\"}, \
      {\"name\": \"uniq_dst_ips\", \"type\": \"int\"}, \
      {\"name\": \"uniq_pkt_sizes\", \"type\": \"int\"}, \
      {\"name\": \"uniq_ttls\", \"type\": \"int\"}, \
      {\"name\": \"uniq_src_ports\", \"type\": \"int\"}, \
      {\"name\": \"uniq_tcp_flags\", \"type\": \"int\"}, \
      {\"name\": \"first_syn_length\", \"type\": \"int\"}, \
      {\"name\": \"first_tcp_rwin\", \"type\": \"int\"}, \
      {\"name\": \"common_pktsizes\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_pktsize_freqs\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_ttls\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_ttl_freqs\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_srcports\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_srcport_freqs\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_tcpflags\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"common_tcpflag_freqs\", \"type\": { \"type\": \"array\", \"items\": \"long\"}}, \
      {\"name\": \"maxmind_continent\", \"type\": \"string\"}, \
      {\"name\": \"maxmind_country\", \"type\": \"string\"}, \
      {\"name\": \"netacq_continent\", \"type\": \"string\"}, \
      {\"name\": \"netacq_country\", \"type\": \"string\"}, \
      {\"name\": \"prefix2asn\", \"type\": \"long\"} \
      ]}";

#define SLASH16_MASK (0x00FF0000)
#define SLASH24_MASK (0x00FFFF00)

#define FT_KEY(ft, mask) \
    ((((uint64_t)(ntohl(flowtuple_data_get_src_ip(ft)))) << 32) | \
    ((((uint64_t)flowtuple_data_get_dest_ip(ft)) & mask) << 8) | \
    ((uint16_t)ntohs(flowtuple_data_get_dest_port(ft))))

#define FT3_KEY(ft, mask) \
    ((((uint64_t)(ft.src_ip)) << 32) | \
    ((((uint64_t)(ft.dst_ip)) & mask) << 8) | \
    ((uint16_t)ft.dst_port))

#define FT_ICMP_KEY(ft, mask) \
    ((((uint64_t)(ntohl(flowtuple_data_get_src_ip(ft)))) << 32) | \
    ((((uint64_t)flowtuple_data_get_dest_ip(ft)) & mask) << 8) | \
    (((uint16_t)ntohs(flowtuple_data_get_src_port(ft))) << 8) | \
    ((uint16_t)ntohs(flowtuple_data_get_dest_port(ft))))

#define FT3_ICMP_KEY(ft, mask) \
    ((((uint64_t)(ft.src_ip)) << 32) | \
    ((((uint64_t)(ft.dst_ip)) & mask) << 8) | \
    (((uint16_t)ft.src_port) << 8) | \
    ((uint16_t)ft.dst_port))


#define FT_OTHER_KEY(ft, mask) \
    ((((uint64_t)(ntohl(flowtuple_data_get_src_ip(ft)))) << 32) | \
    ((((uint64_t)flowtuple_data_get_dest_ip(ft)) & mask) << 8) | \
    (flowtuple_data_get_protocol(ft)))

#define FT3_OTHER_KEY(ft, mask) \
    ((((uint64_t)(ft.src_ip)) << 32) | \
    ((((uint64_t)(ft.dst_ip)) & mask) << 8) | \
    (ft.protocol))

static inline double QUALITY_RATIO(uint32_t portcnt, uint64_t pkts) {
    if (pkts < 10) {
        if (portcnt < 4) {
            return 1.0;
        }
        if (portcnt < 7) {
            return 0.5;
        }
        return 0.33;
    }
    if (portcnt < 15) {
        return 0.33;
    }
    return 0.2;
}

#define KEY_TO_SRC_IP(k) \
        ((uint32_t)(k >> 32))

#define KEY_TO_DEST_IP(k, mask) \
        ((uint32_t)(0x2c000000 | ((k & (mask << 8)) >> 8)))

#define KEY_TO_DEST_PORT(k) \
        ((uint32_t)(k & 0xFFFF))

#define KEY_TO_ICMP_TYPE(k) \
        ((uint8_t)((k & 0xFF00) >> 8))

#define KEY_TO_ICMP_CODE(k) \
        ((uint8_t)(k & 0xFF))

#define KEY_TO_PROTOCOL(k) \
        ((uint8_t)(k & 0xFF))

typedef struct ft_state {
    Pvoid_t destips;
    Pvoid_t srcports;       // UDP and TCP only
    Pvoid_t ttls;
    Pvoid_t tcpflags;       // TCP only
    Pvoid_t pktsizes;
    uint64_t totalpackets;

    uint16_t tcpsynlen;
    uint16_t tcpsynwinlen;
    uint32_t prefix2asn;
    uint16_t maxmind_continent;
    uint16_t maxmind_country;
    uint16_t netacq_continent;
    uint16_t netacq_country;
} flowtupleState;

struct ftconverter {
    corsaro_avro_writer_t *avrow;
    uint32_t interval;
    uint32_t conv_interval_size;
    uint32_t nextinterval;
    uint32_t destipmask;
    Pvoid_t tcp_tuples;
    Pvoid_t udp_tuples;
    Pvoid_t icmp_tuples;
    Pvoid_t other_tuples;
    uint8_t writereq;
    char *outputtemp;
};

static void usage(char *prog) {
    fprintf(stderr, "Usage for %s\n\n", prog);
    fprintf(stderr, "\t%s -n <dest net size> -I <interval size> -V <version> -o <outputfile> <inputfile> [<inputfile> ...]\n", prog);
    fprintf(stderr, "\nFlowtuples will be written to the output file every <interval size> minutes\n");
    fprintf(stderr, "\nDestination IPs will be aggregated into networks with a prefix length of <dest net size> (16 or 24)\n");
    fprintf(stderr, "\n<version> must be set to the flowtuple version of the srouce file\n");
    fprintf(stderr, "\n<inputfile> must be a flowtuple version 2 or 3 file\n");
    fprintf(stderr, "\n<outputfile> will be the template used to name the avro files that are written using the flowtuple version 4 format\n");
}

/** Concatenates a string onto an existing string buffer, starting
 *  from a given pointer. Basically a strcat() where you supply the
 *  end of the string that you are appending to, rather than having
 *  the function have to find it beforehand.
 *
 *  @param str      The string to add to the existing buffer.
 *  @param bufp     The location in the buffer to start writing the
 *                  new string into.
 *  @param buflim   A pointer to the end of the destination buffer. All
 *                  concatenation will cease when this pointer is
 *                  reached, i.e. the resulting string may be truncated.
 *
 *  @return the pointer to the character *after* the last character
 *          written, which can be used for subsequent calls to stradd.
 */
static char *stradd(const char *str, char *bufp, char *buflim) {
    while(bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

static char *derive_output_name(char *templ, uint32_t interval) {
	char scratch[9500];
    char outname[10000];
    char tsbuf[11];
    char *ptr, *w, *end;
    struct timeval tv;

    end = scratch + sizeof(scratch);
    ptr = templ;
    w = scratch;

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch (*++ptr) {
                case '\0':
                    /* Reached end of naming scheme, stop */
                    --ptr;
                    break;
                case 's':
                    /* Add unix timestamp */
                    snprintf(tsbuf, sizeof(tsbuf), "%u", interval);
                    w = stradd(tsbuf, w, end);
                    continue;
                default:
                    /* Everything should be handled by strftime */
                    --ptr;
            }
        }
        if (w == end)
            break;
        *w++ = *ptr;
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    /* Make sure we terminate our string */
    *w = '\0';

    /* Use strftime() to resolve any remaining format modifiers. Note
     * that we use UTC for any date-time conversions.
     */
    tv.tv_sec = interval;
    strftime(outname, sizeof(outname), scratch, gmtime(&tv.tv_sec));
    return strdup(outname);

}

static int start_avro_writer(struct ftconverter *ftdata) {

	char *outname;
    int ret = 0;

	outname = derive_output_name(ftdata->outputtemp, ftdata->interval);
    if (outname == NULL) {
        fprintf(stderr, "Could not derive suitable output file name for interval %u\n", ftdata->interval);
        return -1;
    }

    if (corsaro_is_avro_writer_active(ftdata->avrow)) {
        corsaro_close_avro_writer(ftdata->avrow);
    }

    ret = corsaro_start_avro_writer(ftdata->avrow, outname, 0);
    free(outname);
    return ret;
}

static inline uint32_t find_quality(struct ftconverter *ftdata, Pvoid_t *map,
        Word_t rangecount, uint64_t totalpkts, uint32_t *keys,
        uint32_t *freqs) {

    Word_t key;
    PWord_t pval;
    int rcint;
    uint32_t count = 0;

    key = 0;
    JLF(pval, *map, key);
    while (pval) {
        if ((uint64_t)(*pval) >= QUALITY_RATIO(rangecount, totalpkts) * totalpkts) {
            keys[count] = (uint32_t)key;
            freqs[count] = (uint32_t)(*pval);
            count ++;
            if (count >= MAX_QUALITY_VALUES) {
                break;
            }
        }
        JLN(pval, *map, key);
    }
    JLFA(rcint, *map);
    return count;
}


static void encode_flowtuple4_avro(flowtupleState *ft, Word_t key,
        uint8_t proto, struct ftconverter *convdata) {

    uint64_t val64;
    uint32_t val32;
    uint16_t val16;
    uint8_t val8;
    uint32_t qualkeys[MAX_QUALITY_VALUES];
    uint32_t qualfreqs[MAX_QUALITY_VALUES];
    uint32_t qualused;
    Word_t destipcnt = 0, srcportcnt = 0, ttlcnt = 0, tcpflagcnt = 0;
    Word_t pktsizecnt = 0;
    char valspace[3];

    if (corsaro_start_avro_encoding(convdata->avrow) < 0) {
        return;
    }

    J1C(destipcnt, ft->destips, 0, -1);
    JLC(srcportcnt, ft->srcports, 0, -1);
    JLC(ttlcnt, ft->ttls, 0, -1);
    JLC(tcpflagcnt, ft->tcpflags, 0, -1);
    JLC(pktsizecnt, ft->pktsizes, 0, -1);

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(convdata->interval), sizeof(convdata->interval)) < 0) {
        return;
    }

    val32 = KEY_TO_SRC_IP(key);
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val32 = KEY_TO_DEST_IP(key, convdata->destipmask);
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    if (proto == 6 || proto == 17 || proto == 1) {
        /* For ICMP, this will give us type-code pair as a 16 bit value */
        val16 = KEY_TO_DEST_PORT(key);
    } else {
        val16 = 0;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }

    val8 = proto;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }

    val64 = ft->totalpackets;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val64), sizeof(val64)) < 0) {
        return;
    }

    val32 = (uint32_t)destipcnt;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val32 = (uint32_t)pktsizecnt;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val32 = (uint32_t)ttlcnt;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val32 = (uint32_t)srcportcnt;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val32 = (uint32_t)tcpflagcnt;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    /* TCP SYN len, which is not present in old FT records */
    val32 = (uint32_t)ft->tcpsynlen;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    /* TCP initial Rwin, which is not present in old FT records */
    val32 = (uint32_t)ft->tcpsynwinlen;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    qualused = find_quality(convdata, &(ft->pktsizes), pktsizecnt,
            ft->totalpackets, qualkeys, qualfreqs);
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualkeys,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualfreqs,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }

    qualused = find_quality(convdata, &(ft->ttls), ttlcnt, ft->totalpackets,
            qualkeys, qualfreqs);
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualkeys,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualfreqs,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }

    qualused = find_quality(convdata, &(ft->srcports), srcportcnt,
            ft->totalpackets, qualkeys, qualfreqs);
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualkeys,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualfreqs,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }

    qualused = find_quality(convdata, &(ft->tcpflags), tcpflagcnt,
            ft->totalpackets, qualkeys, qualfreqs);
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualkeys,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }
    if (corsaro_encode_avro_integer_array(convdata->avrow, qualfreqs,
            sizeof(uint32_t), qualused) < 0) {
        return;
    }

    valspace[0] = (char)(ft->maxmind_continent & 0xff);
    valspace[1] = (char)((ft->maxmind_continent >> 8) & 0xff);
    valspace[2] = '\0';

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                valspace, 2) < 0) {
        return;
    }
    valspace[0] = (char)(ft->maxmind_country & 0xff);
    valspace[1] = (char)((ft->maxmind_country >> 8) & 0xff);
    valspace[2] = '\0';

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                valspace, 2) < 0) {
        return;
    }

    valspace[0] = (char)(ft->netacq_continent & 0xff);
    valspace[1] = (char)((ft->netacq_continent >> 8) & 0xff);
    valspace[2] = '\0';

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                valspace, 2) < 0) {
        return;
    }
    valspace[0] = (char)(ft->netacq_country & 0xff);
    valspace[1] = (char)((ft->netacq_country >> 8) & 0xff);
    valspace[2] = '\0';

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                valspace, 2) < 0) {
        return;
    }

    /* source ASN */
    val32 = ft->prefix2asn;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }
}

static inline void update_single(Pvoid_t *map, Word_t key, uint32_t packets) {

    PWord_t pval;
    JLG(pval, *map, key);
    if (!pval) {
        JLI(pval, *map, key);
        *pval = (Word_t)0;
    }
    (*pval) = (*pval) + packets;
}

static void write_tuples(struct ftconverter *ftdata, Pvoid_t *tuples,
        uint8_t proto) {

    Word_t key;
    PWord_t pval;
    int rcint;
    flowtupleState *state = NULL;

    key = 0;
    JLF(pval, *tuples, key);
    while (pval) {
        state = (flowtupleState *)(*pval);

        if (proto == 6 || proto == 17 || proto == 1) {
            encode_flowtuple4_avro(state, key, proto, ftdata);
        } else {
            uint8_t protocol;
            protocol = KEY_TO_PROTOCOL(key);
            encode_flowtuple4_avro(state, key, protocol, ftdata);
        }

        J1FA(rcint, state->destips);
        free(state);
        JLN(pval, *tuples, key);
        if (corsaro_append_avro_writer(ftdata->avrow, NULL) < 0) {

        }
    }
    JLFA(rcint, *tuples);
}

static void update_tuples_ft2(struct ftconverter *ftdata, Pvoid_t *tuples,
        flowtuple_data_t *ft, uint8_t proto) {

    Word_t key;
    PWord_t pval;
    flowtupleState *state = NULL;
    int rcint;
    uint32_t packets;

    packets =  ntohl(flowtuple_data_get_packet_count(ft));

    if (proto == 6 || proto == 17) {
        key = (Word_t)FT_KEY(ft, ftdata->destipmask);
    } else if (proto == 1) {
        key = (Word_t)FT_ICMP_KEY(ft, ftdata->destipmask);
    } else {
        key = (Word_t)FT_OTHER_KEY(ft, ftdata->destipmask);
    }

    JLG(pval, *tuples, key);

    if (!pval) {
        state = calloc(1, sizeof(flowtupleState));
        state->tcpsynlen = 0;
        state->tcpsynwinlen = 0;
        state->prefix2asn = 0;
        state->maxmind_continent = ((uint16_t)'?') + (((uint16_t)'?') << 8);
        state->maxmind_country = ((uint16_t)'?') + (((uint16_t)'?') << 8);
        state->netacq_continent = ((uint16_t)'?') + (((uint16_t)'?') << 8);
        state->netacq_country = ((uint16_t)'?') + (((uint16_t)'?') << 8);
        JLI(pval, *tuples, key);
        *pval = (Word_t)state;
    } else {
        state = (flowtupleState *)(*pval);
    }

    key = (flowtuple_data_get_dest_ip(ft) & 0x0000FFFF);
    J1S(rcint, state->destips, key);

    if (proto == 6) {
        update_single(&(state->srcports),
                ntohs(flowtuple_data_get_src_port(ft)), packets);
        update_single(&(state->tcpflags), flowtuple_data_get_tcp_flags(ft),
                packets);
    } else if (proto == 17) {
        update_single(&(state->srcports),
                ntohs(flowtuple_data_get_src_port(ft)), packets);
    }

    update_single(&(state->ttls), flowtuple_data_get_ttl(ft), packets);
    update_single(&(state->pktsizes), ntohs(flowtuple_data_get_ip_len(ft)),
            packets);

    state->totalpackets += packets;
    //state->totalpackets += 1;

}

static void convert_ft3(corsaro_avro_reader_t *avreader,
        struct ftconverter *ftdata) {

    struct corsaro_flowtuple_data ft3;
    int ret = 1;
    avro_value_t *record;
    uint8_t proto;
    Word_t key;
    PWord_t pval;
    flowtupleState *state = NULL;
    int rcint;
    uint32_t packets;
    Pvoid_t *tuples;

    while (1) {
        ret = corsaro_read_next_avro_record(avreader, &record);
        if (ret <= 0) {
            break;
        }

        decode_flowtuple_from_avro(record, &ft3);
        if (ftdata->interval == 0) {
            ftdata->interval = ft3.interval_ts -
                    (ft3.interval_ts % (ftdata->conv_interval_size * 60));
            ftdata->nextinterval = ft3.interval_ts +
                    (ftdata->conv_interval_size * 60);
        }

        while (ft3.interval_ts >= ftdata->nextinterval) {
            if (ftdata->writereq != 0) {
                if (start_avro_writer(ftdata) < 0) {
                    fprintf(stderr, "error starting Avro writer for interval %u\n", ftdata->interval);
                } else {
                    write_tuples(ftdata, &ftdata->icmp_tuples, 1);
                    write_tuples(ftdata, &ftdata->tcp_tuples, 6);
                    write_tuples(ftdata, &ftdata->udp_tuples, 17);
                    write_tuples(ftdata, &ftdata->other_tuples, 0);
                    ftdata->writereq = 0;
                    fprintf(stderr, "interval %u complete\n",
                            ftdata->interval);
                    corsaro_close_avro_writer(ftdata->avrow);
                }
            }
            ftdata->interval = ftdata->nextinterval;
            ftdata->nextinterval += (ftdata->conv_interval_size * 60);
        }

        ftdata->writereq = 1;
        proto = ft3.protocol;
        packets = ft3.packet_cnt;

        if (proto == 6) {
            tuples = &(ftdata->tcp_tuples);
            key = FT3_KEY(ft3, ftdata->destipmask);
        } else if (proto == 17) {
            tuples = &(ftdata->udp_tuples);
            key = FT3_KEY(ft3, ftdata->destipmask);
        } else if (proto == 1) {
            tuples = &(ftdata->icmp_tuples);
            key = FT3_ICMP_KEY(ft3, ftdata->destipmask);
        } else {
            tuples = &(ftdata->other_tuples);
            key = FT3_OTHER_KEY(ft3, ftdata->destipmask);
        }

        JLG(pval, *tuples, key);

        if (!pval) {
            state = calloc(1, sizeof(flowtupleState));
            state->tcpsynlen = ft3.tcp_synlen;
            state->tcpsynwinlen = ft3.tcp_synwinlen;
            state->prefix2asn = ft3.prefixasn;
            state->maxmind_country = ft3.maxmind_country;
            state->maxmind_continent = ft3.maxmind_continent;
            state->netacq_country = ft3.netacq_country;
            state->netacq_continent = ft3.netacq_continent;
            JLI(pval, *tuples, key);
            *pval = (Word_t)state;
        } else {
            state = (flowtupleState *)(*pval);
        }

        key = (ft3.dst_ip) & 0x0000FFFF;
        J1S(rcint, state->destips, key);

        if (proto == 6) {
            update_single(&(state->srcports), ft3.src_port, packets);
            update_single(&(state->tcpflags), ft3.tcp_flags, packets);
        } else if (proto == 17) {
            update_single(&(state->srcports), ft3.src_port, packets);
        }

        update_single(&(state->ttls), ft3.ttl, packets);
        update_single(&(state->pktsizes), ft3.ip_len, packets);

        state->totalpackets += packets;
    }

}

static void convert_ft2(flowtuple_record_t *record, void *args) {
    struct ftconverter *ftdata = (struct ftconverter *)args;
    flowtuple_record_type_t type = flowtuple_record_get_type(record);
    flowtuple_interval_t *ival;
    flowtuple_data_t *data;
    uint8_t proto;
    uint32_t newinterval;

    switch(type) {
        case FLOWTUPLE_RECORD_TYPE_INTERVAL:
            ival = flowtuple_record_get_interval(record);
            newinterval = ntohl(flowtuple_interval_get_time(ival));

            if (ftdata->interval == 0) {
                ftdata->interval = newinterval - (newinterval % (ftdata->conv_interval_size * 60));
                ftdata->nextinterval = newinterval + (ftdata->conv_interval_size * 60);
                break;
            }

            while (newinterval >= ftdata->nextinterval) {
                if (ftdata->writereq != 0) {
                    if (start_avro_writer(ftdata) < 0) {
                        fprintf(stderr, "error starting Avro writer for interval %u\n", ftdata->interval);
                    } else {
                        write_tuples(ftdata, &ftdata->icmp_tuples, 1);
                        write_tuples(ftdata, &ftdata->tcp_tuples, 6);
                        write_tuples(ftdata, &ftdata->udp_tuples, 17);
                        write_tuples(ftdata, &ftdata->other_tuples, 0);
                        ftdata->writereq = 0;
                        fprintf(stderr, "interval %u complete\n",
                                ftdata->interval);
                        corsaro_close_avro_writer(ftdata->avrow);
                    }
                }
                ftdata->interval = ftdata->nextinterval;
                ftdata->nextinterval += (ftdata->conv_interval_size * 60);
            }
            break;
        case FLOWTUPLE_RECORD_TYPE_FLOWTUPLE_DATA:
            data = flowtuple_record_get_data(record);

            proto = flowtuple_data_get_protocol(data);
            if (proto == 1) {
                update_tuples_ft2(ftdata, &(ftdata->icmp_tuples), data, proto);
            } else if (proto == 6) {
                update_tuples_ft2(ftdata, &(ftdata->tcp_tuples), data, proto);
            } else if (proto == 17) {
                update_tuples_ft2(ftdata, &(ftdata->udp_tuples), data, proto);
            } else {
                update_tuples_ft2(ftdata, &(ftdata->other_tuples), data, proto);
            }

            ftdata->writereq = 1;
            break;
    }

}

int main(int argc, char **argv) {

    flowtuple_handle_t *h = NULL;
    flowtuple_errno_t fterr;
    corsaro_avro_reader_t *avreader = NULL;

    char *outputfile = NULL;
    corsaro_logger_t *logger = NULL;
    struct ftconverter ftdata;
    uint32_t srcversion = 2;
    uint32_t interval_size = 1;
    uint32_t destnetsize = 16;

    int c, ret = 0, i;
    const struct option long_opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "output", required_argument, NULL, 'o' },
        { "destnetsize", required_argument, NULL, 'n' },
        { "intervalsize", required_argument, NULL, 'I' },
        { "srcversion", required_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 },
    };

    while ((c = getopt_long(argc, argv, ":hn:o:V:I:", long_opts, NULL)) != -1) {
        switch(c) {
            case 'h':
                usage(argv[0]);
                goto endmain;
            case 'n':
                destnetsize = strtoul(optarg, NULL, 0);
                break;
            case 'o':
                outputfile = strdup(optarg);
                break;
            case 'I':
                interval_size = strtoul(optarg, NULL, 0);
                break;
            case 'V':
                srcversion = strtoul(optarg, NULL, 0);
                break;
            default:
                usage(argv[0]);
                goto endmain;
        }

    }

    if (outputfile == NULL) {
        fprintf(stderr, "No output file template specified -- halting\n");
        usage(argv[0]);
        goto endmain;
    }

    if (srcversion != 2 && srcversion != 3) {
        fprintf(stderr, "Invalid srcversion: %u, must be either 2 or 3\n",
                srcversion);
        usage(argv[0]);
        goto endmain;
    }

    if (interval_size == 0) {
        fprintf(stderr, "Interval size must not be zero!\n");
        usage(argv[0]);
        goto endmain;
    }

    if (destnetsize != 16 && destnetsize != 24) {
        fprintf(stderr, "Destination network size must be 16 or 24!\n");
        usage(argv[0]);
        goto endmain;
    }


    logger = init_corsaro_logger("ftconvert", "");

    ftdata.avrow = corsaro_create_avro_writer(logger, NEW_FLOWTUPLE_RESULT_SCHEMA);
    if (ftdata.avrow == NULL) {
        fprintf(stderr, "Unable to create Avro writer\n");
        goto endmain;
    }
    /*
    if (corsaro_start_avro_writer(ftdata.avrow, outputfile, 0) == -1) {
        fprintf(stderr, "Error starting Avro writer\n");
        goto endmain;
    }
    */

    ftdata.interval = 0;
    ftdata.nextinterval = 0;
    if (destnetsize == 16) {
        ftdata.destipmask = SLASH16_MASK;
    } else {
        ftdata.destipmask = SLASH24_MASK;
    }
    ftdata.conv_interval_size = interval_size;
    ftdata.icmp_tuples = NULL;
    ftdata.tcp_tuples = NULL;
    ftdata.udp_tuples = NULL;
    ftdata.other_tuples = NULL;
    ftdata.writereq = 0;
    ftdata.outputtemp = outputfile;

    for (i = optind; i < argc; i++) {

        if (srcversion == 2) {
            h = flowtuple_initialize(argv[i], &fterr);
            if (!h) {
                fprintf(stderr, "Error starting libflowtuple reader\n");
                goto endmain;
            }
            flowtuple_loop(h, -1, convert_ft2, &ftdata);
            flowtuple_release(h);
            h = NULL;
        } else {
            avreader = corsaro_create_avro_reader(logger, argv[i]);
            if (avreader == NULL) {
                fprintf(stderr, "Error starting Avro reader\n");
                goto endmain;
            }
            convert_ft3(avreader, &ftdata);
            corsaro_destroy_avro_reader(avreader);
            avreader = NULL;
        }
    }

endmain:
    if (h) {
        flowtuple_release(h);
    }
    if (avreader) {
        corsaro_destroy_avro_reader(avreader);
    }

    if (ftdata.writereq) {
        if (start_avro_writer(&ftdata) >= 0) {
            write_tuples(&ftdata, &(ftdata.icmp_tuples), 1);
            write_tuples(&ftdata, &(ftdata.tcp_tuples), 6);
            write_tuples(&ftdata, &(ftdata.udp_tuples), 17);
            write_tuples(&ftdata, &(ftdata.other_tuples), 0);
        } else {
            fprintf(stderr, "Error starting avro writer for final interval\n");
        }
    }

    if (ftdata.avrow) {
        corsaro_destroy_avro_writer(ftdata.avrow);
    }

    if (outputfile) {
        free(outputfile);
    }

    return ret;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
