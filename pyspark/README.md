# STARDUST pyspark helper

Python class to assist users with performing analysis on STARDUST
data (e.g. flowtuple data) using pyspark.

## Usage
```python

import stardust

sd = stardust.StardustPysparkHelper("telescope-ucsdnt-flowtuple",
        "ucsdnt", "ucsdnt")
sd.startSparkSession("mysparkapp")

# get all flowtuples in the given time range
fts = sd.getFlowtuplesByTimeRange(1574352000, 1574356000)

# run an SQL query against the flowtuples
query_result = sd.runSQLAgainstFlowtuples(fts, "flowtuples",
        "SELECT * FROM flowtuples WHERE ttl > 200 AND tcp_synlen = 20")

# print the number of matching flowtuples from the query
print query_result.count()

# print first 20 results from the query
for r in query_result.limit(20).collect():
    print r

# there are also other handy methods, see the module documentation
# (can be accessed using help())
