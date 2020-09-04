

#include "config.h"

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "example_plugin.h"

#define CORSARO_EXAMPLE_MAGIC 0x41424344
#define PLUGIN_NAME "exampleplugin"

/** Note that the naming of the functions etc. in this plugin IS VERY
 *  IMPORTANT. Use the same naming scheme for any plugins that you write,
 *  e.g. corsaro_<X>_plugin, corsaro_<X>_alloc, corsaro_<X>_parse_config, etc.
 *
 *  This is required for the GENERATE_X_PTRS macros to work correctly and
 *  therefore for your plugin to build.
 */

/* This structure defines the plugin itself to the base corsarotrace instance,
 * including all of the callback functions. Most of the function prototypes
 * are auto-generated by macros, but will require you to name your functions
 * very carefully (see above).
 *
 * #define CORSARO_PLUGIN_ID_EXAMPLE in libcorsaro_plugin.h
 * MAGIC can be any four character sequence, but should be unique to this
 * plugin.
 */
static corsaro_plugin_t corsaro_example_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_EXAMPLE,
    CORSARO_EXAMPLE_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_example),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_example),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_example),
    CORSARO_PLUGIN_GENERATE_TAIL

};

/* This function just needs to return an instance of the corsaro_plugin_t
 * structure defined above.
 */
corsaro_plugin_t *example_plugin_alloc(void) {
    return &corsaro_example_plugin;
}

/* Use this function to parse the plugin specific config provided in the
 * corsarotrace configuration file.
 *
 * options will point at the YAML node containing the mapping object where
 * the plugin-specific options have been parsed.
 *
 * See corsaro_flowtuple_parse_config() in
 * https://github.com/CAIDA/corsaro3/blob/master/libcorsaro/plugins/corsaro_flowtuple.c
 * for a worked example of this callback.
 */
int corsaro_example_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {
    return 0;
}

/* This function is called when all of the configuration file has been
 * parsed and allows you to complete any post-config tasks that may be
 * required, such as logging the final configuration.
 *
 * stdopts and zmq_ctxt are passed in to allow the plugin to access some
 * specific global state that would have been configuration-dependent.
 *
 * Most plugin writers can ignore this function for now...
 */
int corsaro_example_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    return 0;
}

/* Called when corsarotrace is about to exit to allow the plugin to
 * release any memory or resources that it has acquired during the
 * configuration process.
 *
 * Here is where you would free any memory allocated during config parsing,
 * for instance.
 */
void corsaro_example_destroy_self(corsaro_plugin_t *p) {
    return;
}

/* Called when corsarotrace first starts this plugin. Use this function to
 * allocate and initialise any plugin-specific state (for processing only).
 *
 * You should return a pointer to any state that you allocate, as this is
 * what will be passed into other processing methods as the `local`
 * parameter.
 */
void *corsaro_example_init_processing(corsaro_plugin_t *p, int threadid) {

    uint64_t *state;

    state = (uint64_t *)calloc(1, sizeof(uint64_t));
    return state;

}

/* Called when corsarotrace is about to cease processing. Use this function
 * to free any memory allocated as plugin-specific state for processing.
 */
int corsaro_example_halt_processing(corsaro_plugin_t *p, void *local) {

    uint64_t *state = (uint64_t *)local;

    if (state) {
        free(state);
    }

}

/* Given a timestamp and the processing thread ID, this method is intended
 * to return a suitable output file name.
 *
 * This method being public is somewhat of a relic from earlier code designs,
 * so can be ignored by most plugin writers.
 */
char *corsaro_example_derive_output_name(corsaro_plugin_t *p, void *local,
        uint32_t timestamp, int threadid) {

    return (char *)"/tmp/doesnotmatter";

}

/* Function that is called when the first packet is seen that matches a
 * time interval. This method should be used to initialise any per-interval
 * state or statistics for a processing thread, e.g. if you were counting
 * packets per interval, then you would reset your counters to zero in this
 * method.
 */
int corsaro_example_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    uint64_t *state = (uint64_t *)local;
    *state = 0;
}

/* Function that is called at the end of a time interval. This method should
 * be used to produce the final result for this particular processing thread
 * for the ending interval.
 *
 * The return value of this function should be a pointer to memory holding
 * any results that you want to be passed to the merging thread to be combined
 * with results from the other processing threads.
 *
 * For example, if we wanted a single combined packet count as our final
 * result, we would need to return a pointer to this thread's packet count to
 * be passed on to the merging thread.
 * NOTE: the pointer returned from this method must NOT point to memory being
 * used to store local state for this processing thread -- the processing and
 * merging threads will run concurrently, so they cannot both be using the
 * same memory. Always make a COPY of any data that you want to pass to the
 * merging thread.
 */
void *corsaro_example_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    uint64_t *state = (uint64_t *)local;
    uint64_t *retval = calloc(1, sizeof(uint64_t));

    /* copy the result into a new uint64_t */
    memcpy(retval, state, sizeof(uint64_t));
    corsaro_log(p->logger, "processed %lu packets this interval", *state);
    return retval;
}

/* This function is called for each packet received by a processing thread.
 *
 * This is where you can analyse the packet and update any running statistics
 * or state.
 *
 * The libtrace packet can be processed using any libtrace packet processing
 * functions (e.g. trace_get_transport(), trace_get_source_port(), etc.
 *
 * The tags structure contains some pre-extracted features about the packet,
 * including source and destination port, IP protocol and whether the packet
 * was spoofed.
 *
 * See https://github.com/CAIDA/corsaro3/blob/master/libcorsaro/libcorsaro_tagging.h for the full set of available tags.
 *
 * Depending on your data source, netacq, maxmind and prefixasn tags may be
 * unavailable -- you can use the provider_used bitmask to check if these
 * tags are valid or not (see corsaro_flowtuple_process_packet() for an
 * example of how to check the validity of these tags).
 */
int corsaro_example_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    uint64_t *state = (uint64_t *)local;
    (*state) += 1;
    return 0;
}

/* Initialises the state for the merging thread. This thread will combine
 * the results from each processing thread into a single result, once per
 * interval.
 *
 * Use this function to initialise any thread-level state that you will
 * need in your merging thread.
 *
 * As with the init_processing method, you should return a pointer to your
 * thread-level state so that it can be passed into the other merging thread
 * methods.
 *
 * Note that, depending on your analysis, you may not need any merging at all.
 * In that case, feel free to leave these merging methods as is and otherwise
 * ignore them.
 */
void *corsaro_example_init_merging(corsaro_plugin_t *p, int sources) {

    uint64_t *state;

    state = (uint64_t *)calloc(1, sizeof(uint64_t));
    return state;
}

/* When your merging thread is halted, this method will be called. It should
 * be used to free any memory that was allocated as part of your thread-level
 * state.
 */
int corsaro_example_halt_merging(corsaro_plugin_t *p, void *local) {

    uint64_t *state = (uint64_t *)local;
    if (state) {
        free(state);
    }
    return 0;
}

/* This method is called once per interval and is where you will need to
 * provide the code necessary to merge each processing thread's individual
 * results into a single result for that interval (if required).
 *
 * tomerge is an array of pointers, where each element of the array is a
 * pointer that was returned by a processing thread when the end_interval
 * method was called on that thread.
 *
 * The structure pointed to by fin describes the interval that the results
 * belong to. The key members of fin are:
 *    timestamp -- the unix timestamp of the start of the interval
 *    interval_id -- the cardinal identifier of the interval
 *    threads_ended -- the number of processing threads that are running
 *                     (i.e. the size of the tomerge array)
 *
 * Don't forget to free the items in the tomerge array when you're done
 * merging!
 */
int corsaro_example_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin, void *tagsock) {

    int i;
    uint64_t *state = (uint64_t *)local;
    *state = 0;
    for (i = 0; i < fin->threads_ended; i++) {
        uint64_t *val = (uint64_t *)(tomerge[i]);
        (*state) += (*val);

        /* make sure to free each result value, as this was malloced by
         * its processing thread.
         */
        free(val);
    }
    corsaro_log(p->logger, "combined total was %lu packets this interval", *state);
    return 0;
}

/* This function will be called by the merging thread whenever you are due
 * to rotate any output files that you have created (based on the number
 * of intervals that have passed and the `rotatefreq` config option).
 *
 * In this method, you should close any output files you have open. The
 * next set of output files should be opened by the merge_interval_results()
 * method when it is next called.
 */
int corsaro_example_rotate_output(corsaro_plugin_t *p, void *local) {

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
