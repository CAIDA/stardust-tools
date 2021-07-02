# STARDUST pyspark helper

Python class to assist users with performing analysis on STARDUST
data (e.g. flowtuple data) using pyspark.

## Usage
```python

import stardust

# arguments are (swift container, datasource, filename prefix)
sd = stardust.StardustPysparkHelper("telescope-ucsdnt-avro-flowtuple-v4-2021",
        "ucsd-nt", "v3_5min")

# first argument is the name you want to assign to this spark job
# second argument is the maximum number of concurrent tasks to run
sd.startSparkSession("mysparkapp", 4)

# get all flowtuples in the given time range
fts = sd.getFlowtuplesByTimeRange(1574352000, 1574356000)

# run an SQL query against the flowtuples
query_result = sd.runSQLAgainstFlowtuples(fts, "flowtuples",
        "SELECT * FROM flowtuples WHERE uniq_dst_ips > 3000" + \
        " AND first_syn_length = 20")

# print the number of matching flowtuples from the query
print query_result.count()

# print first 20 results from the query
for r in query_result.limit(20).collect():
    print r


# there are also other handy methods, see the module documentation
# (can be accessed using help())
