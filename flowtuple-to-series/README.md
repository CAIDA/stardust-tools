### avro_flowtuple_to_series.py

Processes a flowtuple avro file to generate time series in the style of
the corsaro "report" plugin.

This version of the script is more of a proof of concept right now --
further development would be required to be usable in production. In
particular, we need to be able to use libtimeseries to push the output
into Kafka / DBATS and need to add support for counting unique IPs using
the aggregation methods that the report plugin now supports (for
consistency reasons).

#### Usage
```python3 ./avro_flowtuple_to_series.py <avro file> <mode>```

Valid modes are:
 * 'unfiltered'
 * 'unfiltered-ipmeta'
 * 'nonspoofed'
 * 'unrouted-nonspoofed'

The time series generated will match the high-level filter specified by the
`mode` argument. Unfiltered is split into two modes for workload-balancing
reasons -- the `ipmeta` mode will generate time series for ASN and
geo-location data and regular `unfiltered` will generate the summary, ICMP,
IP protocol, and transport ports series'.


#### Output
The current version of this script simply writes output to standard output
with each space-separated line representing a single data point.

Format of the standard output lines is:
<timestamp> <metric class> <metric value> <counter name> <counter value>

Output directly into kafka, matching the format that we use with the tracets
production instances, is on the TODO list.

#### Notes

This script is not particularly fast and only runs using a single thread.
However, you should be able to run multiple concurrent instances of it and
trust that whatever is consuming your output can deal with data arriving
that is not in strict chronological order -- hopefully this is true for
Kafka.

Expect upwards of 30 minutes to process a single 1 minute flowtuple avro file.

You can expect `unfiltered` mode to use a decent amount of memory as well, at
least 12 GB. The other modes should use far less.

Avro flowtuple data cannot be used to generate the following time series:
 * any series for 'non-erratic' traffic
 * geo-location at the regional or county level
 * filtering performance statistics
 * maxmind geo-location (for now, once we enable maxmind on the flowtuple
   generating instances of corsarotrace then this will work)
