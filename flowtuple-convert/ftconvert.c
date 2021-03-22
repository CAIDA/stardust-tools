
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <flowtuple.h>
#include <libcorsaro_avro.h>
#include <libcorsaro_log.h>

static const char FLOWTUPLE_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\":\"org.caida.corsaro\",\
  \"name\":\"flowtuple\",\
  \"doc\":\"A Corsaro FlowTuple record. All byte fields are in network byte order.\",\
  \"fields\":[\
      {\"name\": \"time\", \"type\": \"long\"}, \
      {\"name\": \"src_ip\", \"type\": \"long\"}, \
      {\"name\": \"dst_ip\", \"type\": \"long\"}, \
      {\"name\": \"src_port\", \"type\": \"int\"}, \
      {\"name\": \"dst_port\", \"type\": \"int\"}, \
      {\"name\": \"protocol\", \"type\": \"int\"}, \
      {\"name\": \"ttl\", \"type\": \"int\"}, \
      {\"name\": \"tcp_flags\", \"type\": \"int\"}, \
      {\"name\": \"ip_len\", \"type\": \"int\"}, \
      {\"name\": \"tcp_synlen\", \"type\": \"int\"}, \
      {\"name\": \"tcp_synwinlen\", \"type\": \"int\"}, \
      {\"name\": \"packet_cnt\", \"type\": \"long\"}, \
      {\"name\": \"is_spoofed\", \"type\": \"int\"}, \
      {\"name\": \"is_masscan\", \"type\": \"int\"}, \
      {\"name\": \"maxmind_continent\", \"type\": \"string\"}, \
      {\"name\": \"maxmind_country\", \"type\": \"string\"}, \
      {\"name\": \"netacq_continent\", \"type\": \"string\"}, \
      {\"name\": \"netacq_country\", \"type\": \"string\"}, \
      {\"name\": \"prefix2asn\", \"type\": \"long\"} \
      ]}";

struct ftconverter {
    corsaro_avro_writer_t *avrow;
    uint32_t interval;
};

static void usage(char *prog) {
    fprintf(stderr, "Usage for %s\n\n", prog);
    fprintf(stderr, "\t%s -i <inputfile> -o <outputfile>\n", prog);
    fprintf(stderr, "\n<inputfile> must be an old corsaro2 flowtuple file\n");
    fprintf(stderr, "\n<outputfile> will be an avro file using the corsaro3 flowtuple schema\n");
}

static void encode_oldft_as_avro(flowtuple_data_t *ft,
        struct ftconverter *convdata) {

    uint32_t val32;
    uint16_t val16;
    uint8_t val8;

    if (corsaro_start_avro_encoding(convdata->avrow) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(convdata->interval), sizeof(convdata->interval)) < 0) {
        return;
    }

    /* libflowtuple gives us the IPs in network byte order UNLESS
     * the dest IP is written in the /8 format. In that case, it ends up
     * being returned in host byte order, because of an oversight in
     * libflowtuple.
     *
     * We could try and fix libflowtuple, but it is easier for now for
     * us to simply try and account for the discrepancy.
     */
    val32 = ntohl(flowtuple_data_get_src_ip(ft));
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    if (flowtuple_data_is_slash_eight(ft)) {
        val32 = flowtuple_data_get_dest_ip(ft) | 0x2c000000;
    } else {
        val32 = ntohl(flowtuple_data_get_dest_ip(ft));
    }

    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    val16 = ntohs(flowtuple_data_get_src_port(ft));
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }

    val16 = ntohs(flowtuple_data_get_dest_port(ft));
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }

    val8 = flowtuple_data_get_protocol(ft);
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }

    val8 = flowtuple_data_get_ttl(ft);
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }

    val8 = flowtuple_data_get_tcp_flags(ft);
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }

    val16 = ntohs(flowtuple_data_get_ip_len(ft));
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }

    /* synlen and synwinlen */
    val16 = 0;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val16), sizeof(val16)) < 0) {
        return;
    }

    val32 = ntohl(flowtuple_data_get_packet_count(ft));
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

    /* is spoofed and is masscan flags */
    val8 = 0;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val8), sizeof(val8)) < 0) {
        return;
    }

    /* Geo-location tags */
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
        return;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
        return;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
        return;
    }
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
        return;
    }

    /* source ASN */
    val32 = 0;
    if (corsaro_encode_avro_field(convdata->avrow, CORSARO_AVRO_LONG,
            &(val32), sizeof(val32)) < 0) {
        return;
    }

}

static void convert_ft(flowtuple_record_t *record, void *args) {
    struct ftconverter *ftdata = (struct ftconverter *)args;
    flowtuple_record_type_t type = flowtuple_record_get_type(record);
    flowtuple_interval_t *ival;
    flowtuple_data_t *data;

    switch(type) {
        case FLOWTUPLE_RECORD_TYPE_INTERVAL:
            ival = flowtuple_record_get_interval(record);
            ftdata->interval = ntohl(flowtuple_interval_get_time(ival));
            break;
        case FLOWTUPLE_RECORD_TYPE_FLOWTUPLE_DATA:
            data = flowtuple_record_get_data(record);
            encode_oldft_as_avro(data, ftdata);
            if (corsaro_append_avro_writer(ftdata->avrow, NULL) < 0) {

            }
            break;
    }

}

int main(int argc, char **argv) {

    flowtuple_handle_t *h = NULL;
    flowtuple_errno_t fterr;

    char *inputfile = NULL;
    char *outputfile = NULL;
    corsaro_logger_t *logger = NULL;
    struct ftconverter ftdata;

    int c, ret = 0;
    const struct option long_opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "input", required_argument, NULL, 'i' },
        { "output", required_argument, NULL, 'o' },
        { NULL, 0, NULL, 0 },
    };

    while ((c = getopt_long(argc, argv, ":hi:o:", long_opts, NULL)) != -1) {
        switch(c) {
            case 'h':
                usage(argv[0]);
                goto endmain;
            case 'i':
                inputfile = strdup(optarg);
                break;
            case 'o':
                outputfile = strdup(optarg);
                break;
            default:
                usage(argv[0]);
                goto endmain;
        }

    }

    if (inputfile == NULL) {
        fprintf(stderr, "No input file specified -- halting\n");
        usage(argv[0]);
        goto endmain;
    }

    if (outputfile == NULL) {
        fprintf(stderr, "No output file specified -- halting\n");
        usage(argv[0]);
        goto endmain;
    }

    logger = init_corsaro_logger("ftconvert", "");

    ftdata.avrow = corsaro_create_avro_writer(logger, FLOWTUPLE_RESULT_SCHEMA);
    if (corsaro_start_avro_writer(ftdata.avrow, outputfile, 1) == -1) {
        fprintf(stderr, "Error starting Avro writer\n");
        goto endmain;
    }

    ftdata.interval = 0;

    h = flowtuple_initialize(inputfile, &fterr);
    flowtuple_loop(h, -1, convert_ft, &ftdata);

endmain:
    if (h) {
        flowtuple_release(h);
    }

    if (ftdata.avrow) {
        corsaro_destroy_avro_writer(ftdata.avrow);
    }

    if (inputfile) {
        free(inputfile);
    }
    if (outputfile) {
        free(outputfile);
    }

    return ret;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
