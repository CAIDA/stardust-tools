# This software is Copyright (C) 2019-2021 The Regents of the University of
# California. All Rights Reserved. Permission to copy, modify, and distribute
# this software and its documentation for educational, research and non-profit
# purposes, without fee, and without a written agreement is hereby granted,
# provided that the above copyright notice, this paragraph and the following
# three paragraphs appear in all copies. Permission to make commercial use of
# this software may be obtained by contacting:
#
# Office of Innovation and Commercialization
# 9500 Gilman Drive, Mail Code 0910
# University of California
# La Jolla, CA 92093-0910
# (858) 534-5815
# invent@ucsd.edu
#
# This software program and documentation are copyrighted by The Regents of the
# University of California. The software program and documentation are supplied
# "as is", without any accompanying services from The Regents. The Regents does
# not warrant that the operation of the program will be uninterrupted or
# error-free. The end-user understands that the program was developed for
# research purposes and is advised not to rely exclusively on the program for
# any reason.
#
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
# DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
# LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
# EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
# HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
# OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
# MODIFICATIONS.

import time, calendar
import pyspark, ipaddress
from functools import reduce
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, col, lit, from_unixtime, array
from pyspark.sql.functions import countDistinct
from pyspark.sql.types import BooleanType, IntegerType, StructType


# Simple function to multiply number of packets by the packet size
calcTotalBytes = udf(lambda arr: arr[0] * arr[1], IntegerType())

between = udf(lambda arr, m, n: any((x >= m and x <= n) for x in arr), \
        BooleanType())

class StardustPysparkHelper(object):
    """
    Provides methods that assist with performing analysis on
    STARDUST data using Spark.

    Author: Shane Alcock

    Attributes
    ----------
    spark : SparkSession
        the Spark session being used by the helper instance

    bucket : str
        the name of the S3 bucket where the STARDUST data is located

    source : str
        the datasource for the data to be analysed, e.g. "ucsd-nt"

    prefix : str
        the prefix assigned to each data file to be analysed, e.g. "ucsd-nt"

    ftrotfreq: int
        the frequency at which flowtuple output files are rotated
        (default 300)

    """

    def __init__(self, bucket, source, prefix, ftrotfreq = 300):
        """
        Parameters
        ----------
        bucket: str
            the name of the S3 bucket where the STARDUST data is
            located

        source : str
            the datasource for the data to be analysed, e.g. "ucsd-nt"

        prefix : str
            the prefix assigned to each data file to be analysed, e.g.
            "ucsd-nt"

        ftrotfreq: int
            the frequency at which flowtuple output files are rotated
            (default 300)

        """
        self.spark = None
        self.bucket = bucket
        self.source = source
        self.prefix = prefix
        self.ftrotfreq = ftrotfreq

    def startSparkSession(self, name, partitions):
        """
        Creates a Spark Session with the given name.

        Must be called before attempting to use any analysis methods.

        Parameters
        ----------
        name: str
            the name to be assigned to the new session
        partitions: int
            the number of partitions to create (roughly the number of CPU cores
            to use for concurrent processing)
        """
        self.spark = SparkSession.builder.master("local[%d]" % (partitions)).appName(name).getOrCreate()

    def _getFlowtupleFileList(self, start, end, ftrotfreq):
        """
        Given a start and end time, figures out which flowtuple files
        should be used to populate our data frames.

        This method is a generator function and intended for internal
        use only.

        Parameters
        ----------
        start: int
            The Unix timestamp for the start of the time period to be
            analysed

        end: int
            The Unix timestamp for the end of the time period to be
            analysed

        ftrotfreq: int
            The frequency at which Flowtuple files should have been
            rotated when generated by Corsaro, in seconds.

        Yields
        ------
        The complete path to the next file that may contain flowtuple
        data for the requested time period.
        """

        # XXX assumes that flowtuple files are going to be regularly
        # rotated and that there won't be crashes / breaks in the collection
        # that would result in files having non-aligned timestamps...
        roundstamp = start - (start % ftrotfreq)

        yielded = 0;

        while roundstamp <= end:

            if roundstamp == end and yielded > 0:
                break

            t = time.gmtime(roundstamp)
            yield "s3a://%s/datasource=%s/year=%d/month=%02d/day=%02d/hour=%02d/%s_%u.ft4.avro" % \
                    (self.bucket, self.source, t[0], t[1], t[2], t[3], \
                     self.prefix, roundstamp)
            yielded += 1

            roundstamp += ftrotfreq

        return

    def _load_avro_file(self, fname):
        """
        Attempts to load a single Avro data file into a data frame

        Parameters
        ----------
        fname: str
            the path to the Avro file to be opened and read

        Returns
        -------
        A dataframe containing the contents of the Avro file if
        successful, otherwise None.
        """
        try:
            df = self.spark.read.format("avro").load(fname)
        except pyspark.sql.utils.AnalysisException as e:
            print(e)
            return None

        return df

    # Returns a single DataFrame containing all flowtuple records for a given
    # time period (defined by a start and end time).
    def getFlowtuplesByTimeRange(self, start, end):
        """
        Produces a data frame containing all flowtuple records for a
        given time period (as defined by a start and end time.
        
        Parameters
        ----------
        start: int
            The Unix timestamp for the start of the time period to be
            analysed

        end: int
            The Unix timestamp for the end of the time period to be
            analysed. Note that the end timestamp is *inclusive*, so
            flows with a timestamp matching 'end' will be included in
            the resulting data frame.

        Returns
        -------
        A dataframe containing all flowtuple records for the given time
        period.

        None, if the Spark session has not been started by the user.
        """

        if self.spark is None:
            return None

        schema = StructType([])
        sc = self.spark.sparkContext
        empty = self.spark.createDataFrame(sc.emptyRDD(), schema)

        # First, reduce our workload by limiting the number of Avro
        # files that we try to load.
        flist = self._getFlowtupleFileList(start, end, self.ftrotfreq)

        # Remove any dataframes where no Avro file has existed
        validframes = []
        for r in flist:
            frame = self._load_avro_file(r)
            if frame is not None:
                validframes.append(frame)

        # combine the remaining dataframes into a single dataframe
        unioned = None
        for vf in validframes:
            if unioned is None:
                unioned = vf
            else:
                unioned = unioned.unionAll(vf)

        if unioned is None or unioned.rdd.isEmpty():
            return empty

        # finally, use a quick SQL query to strip out any flowtuples that
        # don't fall in the exact time period requested, due to loading
        # entire hourly (or some other regular period) Avro files into our
        # initial dataframe
        sqlquery = "SELECT * FROM flowtuples WHERE time >= %u and time <= %u" \
                % (int(start), int(end))

        return self.runSQLAgainstFlowtuples(unioned, "flowtuples", sqlquery)

    def _getTopValues(self, ftuples, metric, topn, topbylabel, topagg,
            includeother):

        """
        Internal function that performs the work required to produce the
        results for the getTopValuesByX functions.

        Parameters
        ----------
        ftuples: DataFrame
            the data frame containing the flowtuple records to run the
            query against

        metric: str
            the name of the flow property you want to analyse. Must be a
            valid single-value "column" in the flowtuple Avro output (e.g.
            "dst_port", "maxmind_country").

        topn: int
            the maximum number of ranks to produce individual results for.
            All other values of lower rank will be accumulated into the
            "Other" category. E.g., to get the top 10 values, set this
            to 10. Set to None if you want all ranks in your results.

        topbylabel: str
            the label to use when reporting the raw numbers for a given
            analysis, e.g. "flows" for flow counts, "packets" for packet
            counts.

        topagg: str
            the SQL aggregation function to use to calculate the number of
            flows/packets/etc that belong to a given metric value, e.g.
            "SUM(packet_cnt)" would be required to count packets.

        includeother: boolean
            Set to True if you want the "Other" category included in your
            result dictionary. Set to False to exclude it.

        Returns
        -------
        A dictionary containing the top ranked values for the specified
        property. For each ranked value, the dictionary will contain the
        following entries:
         * rank -- the rank of the value
         * name -- the name assigned to the value
         * '$topbylabel' -- the number of relevant entities matching the value
         * pct -- the proportion (between 0.0 and 1.0) that matched
                  the value
         * cumpct -- the cumulative proportion (between 0.0 and 1.0)
                     that matched the value and any higher-ranked values, i.e.
                     for a value with rank 3, this will be the sum of the
                     proportions for the values of ranks 1, 2 and 3. Useful
                     for plotting a CDF.

        """
        sqlquery = "SELECT %s, %s AS %s from flowtuples GROUP BY %s ORDER BY %s DESC" % (metric, topagg, topbylabel, metric, topbylabel)

        result = {}
        queryres = self.runSQLAgainstFlowtuples(ftuples, "flowtuples", sqlquery)

        rank = 1
        othercount = 0
        totalflows = 0.0
        cumflowpct = 0.0
        for r in queryres.collect():
            totalflows += r[topbylabel]

            if topn is not None and rank > topn:
                othercount += r[topbylabel]
            else:
                result[rank] = {'name': r[metric], 'rank': rank,
                        topbylabel: r[topbylabel]}
                rank += 1

        if othercount > 0 and totalflows is not None:
            result['Other'] = {'name': "Other", 'rank': rank,
                    topbylabel: othercount}

        for k,v in result.items():
            result[k]['pct'] = v[topbylabel] / totalflows
            cumflowpct += result[k]['pct']
            result[k]['cumpct'] = cumflowpct

        return result


    def getTopValuesByFlowCount(self, ftuples, metric, topn, includeother=True):
        """
        For a given flow property, such as geo-located country or destination
        port, return the top N values for that property based on the number
        of flows observed matching that property value.

        For instance, you could use this function to determine the top 10 most
        popular source countries or the top 20 most popular destination ports.

        Parameters
        ----------
        ftuples: DataFrame
            the data frame containing the flowtuple records to run the
            query against

        metric: str
            the name of the flow property you want to analyse. Must be a
            valid single-value "column" in the flowtuple Avro output (e.g.
            "dst_port", "maxmind_country").

        topn: int
            the maximum number of ranks to produce individual results for.
            All other values of lower rank will be accumulated into the
            "Other" category. E.g., to get the top 10 values
            set this to 10. Set to None if you want all ranks in your results.

        includeother: boolean
            Set to True if you want the "Other" category included in your
            result dictionary. Set to False to exclude it.

        Returns
        -------
        A dictionary containing the top ranked values for the specified
        property. For each ranked value, the dictionary will contain the
        following entries:
         * rank -- the rank of the value
         * name -- the name assigned to the value
         * flows -- the number of flows matching that value
         * pct -- the proportion (between 0.0 and 1.0) of flows that match
                  the value
         * cumpct -- the cumulative proportion (between 0.0 and 1.0) of flows
                     that match the value and any higher-ranked values, i.e.
                     for a value with rank 3, this will be the sum of the
                     proportions for the values of ranks 1, 2 and 3. Useful
                     for plotting a CDF.

        """
        if metric not in ftuples.columns:
            return None

        return self._getTopValues(ftuples, metric, topn, "flows", "COUNT(*)",
                includeother)

    def getTopValuesByUniqueDestIpCount(self, ftuples, metric, topn,
            includeother=True):
        """
        For a given flow property, such as geo-located country or destination
        port, return the top N values for that property based on the number
        of unique (source IP, dest IP, protocol, dest port) combinations that
        matched that property value. Combinations are counted once per interval
        that they appear in.

        For instance, you could use this function to determine the top 10 most
        popular source countries or the top 20 most popular destination ports.

        Parameters
        ----------
        ftuples: DataFrame
            the data frame containing the flowtuple records to run the
            query against

        metric: str
            the name of the flow property you want to analyse. Must be a
            valid single-value "column" in the flowtuple Avro output (e.g.
            "dst_port", "maxmind_country").

        topn: int
            the maximum number of ranks to produce individual results for.
            All other values of lower rank will be accumulated into the
            "Other" category. E.g., to get the top 10 values
            set this to 10. Set to None if you want all ranks in your results.

        includeother: boolean
            Set to True if you want the "Other" category included in your
            result dictionary. Set to False to exclude it.

        Returns
        -------
        A dictionary containing the top ranked values for the specified
        property. For each ranked value, the dictionary will contain the
        following entries:
         * rank -- the rank of the value
         * name -- the name assigned to the value
         * flows -- the number of flows matching that value
         * pct -- the proportion (between 0.0 and 1.0) of IP targets
                  that match the value
         * cumpct -- the cumulative proportion (between 0.0 and 1.0) of IPs
                     that match the value and any higher-ranked values, i.e.
                     for a value with rank 3, this will be the sum of the
                     proportions for the values of ranks 1, 2 and 3. Useful
                     for plotting a CDF.

        """
        if metric not in ftuples.columns:
            return None

        return self._getTopValues(ftuples, metric, topn, "dest_ips",
                "SUM(uniq_dst_ips)", includeother)
        return None


    def getTopValuesByPacketCount(self, ftuples, metric, topn,
            includeother=True):

        """
        For a given flow property, such as geo-located country or destination
        port, return the top N values for that property based on the number
        of packets that belonged to flows matching that property value.

        For instance, you could use this function to determine the top 10 most
        popular source countries or the top 20 most popular destination ports.

        Parameters
        ----------
        ftuples: DataFrame
            the data frame containing the flowtuple records to run the
            query against

        metric: str
            the name of the flow property you want to analyse. Must be a
            valid "column" in the flowtuple Avro output (e.g. "dst_port",
            "maxmind_country").

        topn: int
            the maximum number of ranks to produce individual results for.
            All other values of lower rank will be accumulated into the
            "Other" category. E.g., to get the top 10 countries, set this
            to 10. Set to None if you want all ranks in your results.

        includeother: boolean
            Set to True if you want the "Other" category included in your
            result dictionary. Set to False to exclude it.

        Returns
        -------
        A dictionary containing the top ranked values for the specified
        property. For each ranked value, the dictionary will contain the
        following entries:
         * rank -- the rank of the value
         * name -- the name assigned to the value
         * packets -- the number of packets matching that value
         * pct -- the proportion (between 0.0 and 1.0) of packets that match
                  the value
         * cumpct -- the cumulative proportion (between 0.0 and 1.0) of packets
                     that match the value and any higher-ranked values, i.e.
                     for a value with rank 3, this will be the sum of the
                     proportions for the values of ranks 1, 2 and 3. Useful
                     for plotting a CDF.

        """
        if metric not in ftuples.columns:
            return None

        return self._getTopValues(ftuples, metric, topn, "packets",
                "SUM(packet_cnt)", includeother)


    def getFlowtuplesByRecentTime(self, secondsback):
        """
        Produces a data frame containing all flowtuple records for the
        time period starting from now and going back the given number
        of seconds.

        Parameters
        ----------
        secondsback: int
            The number of seconds to go back when fetching flowtuple
            records, e.g. to get the last hour, set this to 3600.

        Returns
        -------
        A data frame containing all flowtuple records observed in
        the most recent 'secondsback' seconds.

        None, if the Spark session has not been started by the user.
        """

        if self.spark is None:
            return None

        curr = int(time.time())
        start = curr - secondsback

        return self.getFlowtuplesByTimeRange(start, curr)

    def getAllFlowtuples(self):
        """
        Loads *all* flowtuple records in a data set into a data frame.

        Be careful -- trying to do analysis against the whole dataset
        at once will probably lead of OOM errors! DO NOT CALL THIS METHOD
        UNLESS YOU KNOW WHAT YOU ARE DOING!

        Returns
        -------
        A data frame containing all flowtuple records in the data set
        described by the bucket and source used by this helper instance.

        None, if the Spark session has not been started by the user.
        """
        if self.spark is None:
            return None

        bpath = "s3a://%s/datasource=%s/" % (self.bucket, self.source)
        df = self.spark.read.format("avro").load(bpath)
        return df

    def runSQLAgainstFlowtuples(self, ftuples, tablename, sqlquery):
        """
        Runs a given SQL query against a data frame of flowtuple records.

        Beware of SQL injection -- only use this method with queries that
        you write yourself (as opposed to being supplied by users).

        Parameters
        ----------
        ftuples: DataFrame
            the data frame containing the flowtuple records to run the
            query against

        tablename: str
            the name to use when converting the flowtuple data frame
            into a temporary view for running the query. This name is
            what you should use in the FROM clause of your query.

        sqlquery: str
            the SQL query to run. Note that the FROM clause in your
            query must match the table you gave as the 'tablename'
            parameter.

        Returns
        -------
        A dataframe containing the results of running your query
        against the flowtuples provided.

        None, if the Spark session has not been started by the user.
        """

        if self.spark is None:
            return None

        if ftuples.rdd.isEmpty():
            return ftuples

        ftuples.createOrReplaceTempView(tablename)
        queryhdl = self.spark.sql(sqlquery)
        return queryhdl


    def _prefixfilter(self, prefix):
        """
        Function that determines whether a given IP address matches a
        given prefix.

        Intended for filtering Flowtuples that match a specific prefix.

        Parameters
        ----------
        prefix: unicode str
            A prefix to filter on, e.g u"192.168.0.0/16"

        Returns
        -------
        A pyspark user-defined function that will return True if an
        IP passed into it matches the prefix or False if the IP
        does not match the prefix.
        """
        def __prefixfilter(src_ip):
            sip = ipaddress.IPv4Address(src_ip)

            if sip in prefix:
                return True
            return False
        return udf(__prefixfilter, BooleanType())



    def filterFlowtuplesByPrefix(self, ftuples, prefix, ftsorted=False,
            limitnum=None):
        """
        Filters a data frame of flowtuple records to only contain
        flowtuples where the source IP matches a specific prefix.

        Parameters
        ----------
        ftuples: DataFrame
            The set of flowtuple records to be filtered.

        prefix: unicode str
            A prefix to filter on, e.g u"192.168.0.0/16"

        ftsorted: bool
            If true, the resulting data frame will be sorted by time,
            then source IP address -- this will increase the time
            required to return a result. Default is False.

        limitnum: int
            Truncate the resulting data frame to only contain at most
            this number of flowtuple records. If None, then return all
            records. Default is None.

        Returns
        -------
        A data frame containing flowtuple records where the source IP
        matches the given prefix.
        """
        pfx = ipaddress.IPv4Network(prefix)

        if "src_ip" not in ftuples.columns:
            return ftuples

        interim = ftuples.where((self._prefixfilter(pfx)(col("src_ip"))))

        if ftsorted and "time" in interim.columns:
            interim = interim.sort(["time", "src_ip"], ascending=[True, True])

        if limitnum is not None:
            interim = interim.limit(limitnum)

        return interim

    def filterFlowtuplesByCommonValue(self, ftuples, metric, ranges):
        """
        Removes all flowtuples that do not have a "common" value, e.g.
        source port, TTL, packet size, that is between one of the provided
        ranges.

        Parameters
        ----------
        ftuples: DataFrame
            The set of flowtuple records to be filtered.

        metric: unicode str
            The name of the field to use when filtering, e.g. "common_ttls".
            The field must be one of the array fields in the flowtuple
            schema.

        ranges: list of 2-tuples
            A list of numeric ranges (expressed as (min, max)) within which
            a common value must be observed to retain a flowtuple in the
            returned DataFrame. Note that ranges are **inclusive**. Multiple
            ranges may be specified.

        Returns
        -------
        A data frame containing flowtuple records where the requested metric
        includes at least one common value within the specified ranges.
        """
        if metric not in ftuples.columns:
            return ftuples

        result = None
        for rmin, rmax in ranges:
            interim = ftuples.where(between(col(metric), lit(rmin), lit(rmax)))

            if result is None:
                result = interim
            else:
                result = result.unionAll(interim)

        return result

    def generateSeriesFromFlowtuples(self, ftuples, label=None,
            metricname=None, metricvalue=None):
        """
        Aggregates the flowtuples in a data frame to produce a time
        series similar to that produced by the corsaro report plugin,
        i.e. packets, bytes, unique source IPs, unique dest IPs,
        unique source ASNs.

        Use this to generate graphable data points after applying
        some transformations to a flowtuple data set.

        Parameters
        ----------
        ftuples: DataFrame
            a data frame containing the flowtuples to be aggregated

        label: str
            The "source label" to be associated with each time series
            datapoint. Defaults to None, which will generate a label
            of "unknown".

        metricname: str
            The name to use to describe the metric class for this
            aggregated data. Defaults to None, which will result in
            a metric name of "unknown".

        metricvalue: str
            The value to use to describe the metric value for this
            aggregated data. Defaults to None, which will result in
            the metric value not being included in the "key" field
            for each data point.

        Returns
        -------
        A data frame containing datapoints that match the format of
        the report plugin output, grouped by timestamp (i.e. one
        datapoint per timestamp).
        """

        if "time" not in ftuples.columns:
            return None

        if label is None:
            label = "unknown"
        if metricname is None:
            metricname = "unknown"

        # This is an attempt to construct a libtimeseries-like key
        # string for the rows that we are producing.
        if metricvalue is not None:
            fulllabel = "%s.%s.%s" % (label, metricname, metricvalue)
        else:
            fulllabel = "%s.%s" % (label, metricname)

        # With FT4, we can't get an accurate byte count anymore since we
        # don't record total bytes for each FT :/

        grouped = ftuples.groupBy(["time"])

        agged = grouped.agg({'packet_cnt': "sum"})\
                .withColumnRenamed('sum(packet_cnt)', "pkt_cnt")

        agged2 = grouped.agg(countDistinct("src_ip"), countDistinct("dst_net"),
                countDistinct("prefix2asn"))\
                .withColumnRenamed("count(DISTINCT src_ip)", "src_ip_cnt")\
                .withColumnRenamed("count(DISTINCT dst_net)", "dest_ip_cnt")\
                .withColumnRenamed("count(DISTINCT prefix2asn)", "src_asn_cnt")

        final = agged.join(agged2, on=["time"], how="left_outer")\
                .withColumn("libts_key", lit(fulllabel))

        return final.sort("time")

    # The first of the "wheres" is used to create what I've called a
    # baseline dataframe, which can be useful to help determine whether
    # the intersection represents a large proportion of the rows that
    # matched a single condition or not.
    #
    # E.g., if I'm interested in the number of Russian-sourced flows that
    # also had a destination port < 1024, I would pass in a list containing two
    # where clauses: ["maxmind_country == 'RU'", "dst_port < 1024"]
    #
    # All flowtuples that match the first clause (country is 'RU') will
    # be returned in the baseline dataframe. Only flowtuples that match
    # *all* clauses are returned in the intersect dataframe.
    def createFlowtupleIntersection(self, ftuples, wheres):
        """
        Reduces a dataframe of flowtuples to the set of flowtuples that
        meet all of a given set of filtering criteria. To aid in
        determining the level of correlation between the criteria, this
        method also returns the set of flowtuples that match just the first
        criteria given (the "baseline").

        Parameters
        ----------
        ftuples : data frame
            a data frame containing the starting set of flowtuples

        wheres : list(str)
            a set of where clauses that will be used as the filtering
            criteria to create the intersection. As noted above, the
            first item in this list will also be used to generate the
            "baseline" result set.

            For example, to get the set of flowtuples where the destination
            port is less than 1024 and the source IP was Russian, we would pass
            in ["netacq_country == 'RU'", "dest_port < 1024"]. The baseline
            result set would then be all flowtuples that have a Russian source
            IP, regardless of destination port.

        Returns
        -------
        A tuple containing two data frames. The first data frame
        consists of all flowtuples in 'ftuples' that match ALL of the
        given criteria in the 'wheres' parameter. The second data
        frame consists of flowtuples in 'ftuples' that matched the
        FIRST criterion in the 'wheres' parameter.
        """

        setbaseline = False
        intersect = ftuples
        baseline = ftuples

        for w in wheres:
            if not setbaseline:
                baseline = ftuples.where(w)
                intersect = baseline
                setbaseline = True
                continue

            intersect = intersect.where(w) 

        return intersect, baseline


def StardustHelperExampleCode():
    """
    Just some examples showing how to use the StardustPysparkHelper
    class -- will only do anything useful if you actually have access
    to my test dataset
    """

    # creating an instance of a helper
    sd = StardustPysparkHelper("telescope-ucsdnt-avro-flowtuple-v4-2021",
            "ucsd-nt", "v3_5min")

    # starting a spark session with the name "test", using 4 partitions (CPUs)
    sd.startSparkSession("test", 4)

    # getting flowtuple records from a specific time range
    range_recs = sd.getFlowtuplesByTimeRange(1612130100, 1612133700)

    # getting the last day's worth of flowtuple records
    lastday_recs = sd.getFlowtuplesByRecentTime(60 * 60 * 24)

    # running a raw SQL query against a flowtuple data frame.
    # WARNING: don't pass user-provided queries directly into this
    # function without doing some sort of sanitization to protect
    # against SQL injection.
    query_df = sd.runSQLAgainstFlowtuples(range_recs, "flowtuples", \
            "SELECT * from flowtuples WHERE uniq_dst_ips > 30000 " + \
            "AND first_syn_length > 24")

    # get the number of flows that matched our query
    print(query_df.count())

    # print the first 20 flows that matched our query
    # ALWAYS use collect() to convert a data frame into a list
    # of rows if you want to inspect the results
    results = query_df.limit(20).collect()
    for r in results:
        # this prints the raw row object, which is fine for debugging but
        # you'll want to do some proper formatting for usable output
        print(r)
    print()


    # filtering a set of flowtuples based on a source IP prefix
    # NOTE: the prefix must be a unicode string
    prefix_df = sd.filterFlowtuplesByPrefix(lastday_recs, u"1.0.0.0/8")

    # finding flowtuples that match a set of filtering criteria
    # base will contain flowtuples with a Russian source IP,
    # sect will contain flowtuples with a Russian source IP that
    # use multiple TTLs.
    sect, base = sd.createFlowtupleIntersection(range_recs,
            ["netacq_country == 'RU'", "uniq_ttls > 1"])

    # generate aggregated report-style time series data for the intersection
    # we just generated
    sect_report = sd.generateReportOutputFromFlowtuples(sect, "example",
            "ftintersect", "RU_multiTTL")

    # generate a second report time series from the baseline (to compare
    # against the intersection data)
    base_report = sd.generateReportOutputFromFlowtuples(base, "example",
            "ftintersect", "RU")

    # again, use collect() to convert our dataframe in rows that we can
    # write as output
    sect_results = sect_report.collect()
    base_results = base_report.collect()

    # dump the time series to stdout as pairs of Row objects
    # this is a bit lazy -- if you were doing this for real,
    # you would want better error checking and output formatting
    for i in range(0, sect_report.count()):
        print(sect_results[i], base_results[i])


    # get all flowtuples where the TTL falls between 20 and 30 OR 70 and 80
    q_res = sd.filterFlowtuplesByCommonValue(range_recs, "common_ttls",
                [(20, 30), (70, 80)])


    # show the top 10 destination ports (by flow count) for Russian source IPs
    # setting the last parameter to True will also include an "Other" category
    topn = sd.getTopValuesByFlowCount(base, "netacq_country", 10, True)
    for k,v in topn.items():
        print(v)

