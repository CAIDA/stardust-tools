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
[plugin-based system](https://github.com/CAIDA/corsaro3/tree/master/libcorsaro/plugins). 
The plugins must be written using the C programming
language and will need to provide callback functions for a set of pre-defined
events. See below for more details on how to write a corsarotrace plugin.

This guide is aimed at new users who are using corsarotrace for the first
time and want to learn how to write simple plugins. Advanced users who want
to write more complicated plugins or need to leverage the full capabilities
of corsaro should also look at 
[README-Advanced.md](https://github.com/CAIDA/stardust-tools/blob/corsarotrace-users/corsarotrace-users/README-Advanced.md).

## Configuring corsarotrace

corsarotrace is configured using a YAML file. The syntax of YAML is beyond the
scope of this document, but can be easily learned through any number of
websites.

An [example YAML configuration file](https://github.com/CAIDA/stardust-tools/blob/corsarotrace-users/corsarotrace-users/corsarotrace-example.yaml)
for corsarotrace is included with this README.

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

``TODO``: This section still needs to be edited.

In the meantime please check the following hello-world example https://github.com/CAIDA/stardust-tools/blob/corsarotrace-users/corsarotrace-users/example_plugin.c
 and https://github.com/CAIDA/stardust-tools/blob/corsarotrace-users/corsarotrace-users/example_plugin.h

Hopefully the documentation within those files should help give you a rough
idea of where your code should be going (and which functions are the most
important to implement and which can be ignored at first).

## Installing your plugin

The following instructions will demonstrate how one would add the example
plugin included in this repo to corsaro, so that it becomes usable within
your corsarotrace install.

First, we assume that you have a cloned copy of the corsaro3 source tree.
In this example, the source tree is located at `/home/limbo/corsaro3` but
feel free to adjust these instructions to match a different location if need be.

In this example, the plugin source and header files are located at
`/home/limbo/example_plugin.c` and `/home/limbo/example_plugin.h`.


 * Copy both your plugin source and plugin header files into the
   `libcorsaro/plugins/` directory within the corsaro3 source tree.


```cp /home/limbo/example_plugin.[ch] /home/limbo/corsaro3/libcorsaro/plugins```


 * Update the `Makefile.am` file in `libcorsaro/plugins` to tell the build
   system to compile your plugin. Place lines like the ones given below just prior to line beginning with `libcorsaroplugins_la_SOURCES =` :

```
PLUGIN_SRC+=example_plugin.c example_plugin.h
include_HEADERS+=example_plugin.h
```

 * Add an entry to the `corsaro_plugin_id_t` enumerated type for your new
   plugin. The enum name must match the `CORSARO_PLUGIN_ID_` name that you
   used in your plugin source code. The value must be an unused number less
   than the value of `CORSARO_PLUGIN_ID_MAX` (or update the value of `MAX`
   to be your new value).

```
typedef enum corsaro_plugin_id {
    CORSARO_PLUGIN_ID_FLOWTUPLE = 20,
    CORSARO_PLUGIN_ID_DOS = 30,
    CORSARO_PLUGIN_ID_EXAMPLE = 40,       // new plugin ID here
    CORSARO_PLUGIN_ID_REPORT = 100,
    CORSARO_PLUGIN_ID_WDCAP = 200,
    CORSARO_PLUGIN_ID_NULL = 205,
    CORSARO_PLUGIN_ID_FILTERINGSTATS = 210,
    CORSARO_PLUGIN_ID_MAX = CORSARO_PLUGIN_ID_FILTERINGSTATS
} corsaro_plugin_id_t;
```

 * Add a `#include` for your new plugin header to
   `libcorsaro/libcorsaro_plugin.c`, just below the line where the
   `corsaro_null.h` header is included.

```
#include "corsaro_null.h"
#include "example_plugin.h"
```

 * Before we start building and installing a new version of corsaro3, it
   will pay to remove any existing packaged versions of the software that
   is on your machine.

```sudo apt remove corsaro3 corsaro3-tools libcorsaro3-dev libcorsaro3```

 * At the base directory of the corsaro3 source tree, run `./bootstrap.sh`
   followed by `./configure`.

 * Now run `make` -- this will compile your plugin and link it into libcorsaro.
   Since this is the first time you've likely been able to compile your
   plugin, you will probably get errors. Try to fix the errors and then keep
   repeating this step until `make` completes successfully.

 * Install the updated corsaro onto your system using
   `sudo make install && sudo ldconfig`.
   The updated version of corsarotrace will be installed into
   `/usr/local/bin` by default.

Now you should be able to create a corsarotrace configuration file that uses
your plugin and run corsarotrace!

### Extra things to try if the new corsarotrace doesn't seem to work

 * Make sure that `/usr/local/bin` is in your `$PATH` environment variable.
 * Add `/usr/local/lib` to your `$LD_LIBRARY_PATH` environment variable.
 * Use `which corsarotrace` to double-check that you are definitely running
   the corsarotrace that you installed to `/usr/local/bin`.
 * Make sure that the plugin name that you give in your configuration file
   exactly matches the name defined in your plugin source code, e.g. for the
   example plugin, the name was defined as `exampleplugin` and declared as
   such in the `corsaro_plugin_t` structure.
