# corsarotrace User Guide
---

corsarotrace is a tool that allows you to run custom analysis code against
captured packets without needing to deal with the overhead of opening the
capture device, performing the capture and decoding packet headers.

corsarotrace leverages the [libtrace](https://github.com/LibtraceTeam/libtrace)
library for capturing and processing packets. Libtrace (and therefore
corsarotrace) is designed to support parallel processing using multiple threads
wherever possible so that users can process large quantities of network traffic
quickly and efficiently.

corsarotrace allows users to run their custom analysis routines through a
plugin-based system. The plugins must be written using the C programming
language and will need to provide callback functions for a set of pre-defined
events. See below for more details on how to write a corsarotrace plugin.

This guide is aimed at new users who are using corsarotrace for the first
time and want to learn how to write simple plugins. Advanced users who want
to write more complicated plugins or need to leverage the full capabilities
of corsaro should also look at README-Advanced.md.

## Configuring corsarotrace

corsarotrace is configured using a YAML file. The syntax of YAML is beyond the
scope of this document, but can be easily learned through any number of
websites.

An example YAML configuration file for corsarotrace is included with this
README (it is called `corsarotrace-example.yaml`).

The corsarotrace configuration includes the following top-level options,
which can be specified using a basic `key: value` syntax:

    packetsource        A libtrace URI describing where the captured packets
                        are to be read from.
                        If you are reading packets from an nDAG multicast
                        group, then this should look something like:
                        ndag:<interface>,<groupaddr>,<beaconport>

                        You can also use corsarotrace to process pcap trace
                        files, in which case you should set your URI to be:
                        pcapfile:<file location>

    logfilename         The name of the file to write log message to. Only
                        applies if the log mode is set to 'file' when you
                        run corsarotrace.

    interval            Specifies the interval length in seconds. Plugins will
                        typically merge and report their results at the end of
                        each interval. Defaults to 60 seconds.

    rotatefreq          Specifies the number of intervals that must complete
                        before triggering a "rotate output" event. This is
                        used by plugins to determine when to close and rotate
                        any open output files.

    threads             The number of threads to use for processing packets.
                        For nDAG inputs, the nDAG owner will tell you the
                        correct number of threads to specify here. For pcap file
                        inputs, the ideal number of threads is 1.

    startboundaryts     Ignore all packets that have a timestamp earlier than
                        the Unix timestamp specified for this option.

    endboundaryts       Ignore all packets that have a timestamp after the
                        Unix timestamp specified for this option.

    removespoofed       If set to 'yes', ignore all packets that have been
                        identified as spoofed. Defaults to 'no'.

    removeerratic       If set to 'yes', ignore all packets that have been
                        identified as an erratic traffic type. Defaults to 'no'.

    removerouted        If set to 'yes', ignore all packets that have a source
                        IP address that is globally routable (i.e. is not an
                        RD5735 address). Defaults to 'no'.

    removenotscan       If set to 'yes', only include packets that have been
                        identified as matching the behaviour of a known
                        large-scale scanning system (e.g. masscan).
                        Defaults to 'no'.

Each corsarotrace instance must run at least one processing plugin, which
defines the analysis that should be performed on each captured packet as well
as how to combine the results from multiple processing threads together into
a single usable result.

Plugins are configured using the following syntax:

    plugins:
     - <plugin name>:
         <plugin option 1>: value
         <plugin option 2>: value
         ...

     - <another plugin name>:
         <plugin option 1>: value
         <plugin option 2>: value

Plugin options are specific to each plugin -- if you are using a plugin that
was included with the corsaro software package, please consult the
documentation of that package for more details as to what options are available
and what they mean.

If you've developed your own plugin, then you should know which configuration
options to provide. Simple plugins may take no options at all, in which case
the configuration should simply be:

    plugins:
      - <simple plugin name>:
      - <another simple plugin name>:


## Running corsarotrace

Once you have a suitable config file, you can run corsarotrace using the
following command

    ./corsarotrace -c <config filename> -l <logmode>

`logmode` may be one of `terminal`, `file`, `syslog` or `disabled`.



## Writing a plugin

TODO

## Installing your plugin

TODO
