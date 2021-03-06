#!/usr/bin/python3

from fastavro import reader
import sys, wandio

def usage(prog):
    print("Usage for %s" % (prog), file=sys.stderr)
    print("\n\t%s <flowtuple file> <mode>" % (prog), file=sys.stderr)
    print("\nSupported modes are 'unfiltered', 'unfiltered-ipmeta', 'nonspoofed' and 'unrouted-nonspoofed'", file=sys.stderr)

    sys.exit(1)


def should_ignore_record(r, mode):
    checknonspoofed = False
    if mode in ["unfiltered", "unfiltered-ipmeta"]:
        return False

    if mode == "unrouted-nonspoofed":
        if (r['src_ip'] & 0xff000000) == 0 or \
                (r['src_ip'] & 0xff000000) == 0x0a000000 or \
                (r['src_ip'] & 0xff000000) == 0x7f000000 or \
                (r['src_ip'] & 0xffff0000) == 0xa9fe0000 or \
                (r['src_ip'] & 0xfff00000) == 0xac100000 or \
                (r['src_ip'] & 0xffffff00) == 0xc0000000 or \
                (r['src_ip'] & 0xffffff00) == 0xc0000200 or \
                (r['src_ip'] & 0xffffff00) == 0xc0586300 or \
                (r['src_ip'] & 0xffff0000) == 0xc0a80000 or \
                (r['src_ip'] & 0xfffe0000) == 0xc6120000 or \
                (r['src_ip'] & 0xffffff00) == 0xc6336400 or \
                (r['src_ip'] & 0xffffff00) == 0xcb007100 or \
                (r['src_ip'] & 0xf0000000) >= 0xe0000000:

            checknonspoofed = True
        else:
            return True

    if checknonspoofed or mode == "nonspoofed":
        if r['is_spoofed'] == 0:
            return False
        if r['is_masscan'] == 1:
            return False


    return True

def is_popular_port(proto, port, is_src):
    if proto == 6:
        if port == 0:
            return False
        if port < 1024:
            return True
        if port == 5000 or port == 5060 or port == 6881:
            return True
        if port == 8080 or port == 8081 or port == 8443:
            return True

    if proto == 17:
        if port == 0:
            return False
        if port < 1024:
            return True
        if port == 5060:
            return True
        if port == 8080 or port == 8081 or port == 8443:
            return True

    return False


def reset_counters(metrics):

    metric_map = {}

    for m in metrics:
        if m == "tcpports" or m == "tcpports-pop":
            metric_map["tcp_src_ports"] = {}
            metric_map["tcp_dst_ports"] = {}
        elif m == "udpports" or m == "udpports-pop":
            metric_map["udp_src_ports"] = {}
            metric_map["udp_dst_ports"] = {}
        elif m == "netacq":
            metric_map["netacq_continents"] = {}
            metric_map["netacq_countries"] = {}
        elif m != 'summary':
            metric_map[m] = {}
        else:
            metric_map[m] = {
                'packets': 0,
                'bytes': 0,
                'uniq_src_ips': set(),
                'uniq_dst_ips': set(),
                'uniq_src_asns': set()
            }

    return metric_map


def update_single_metric(mvals, key, r):
    if key not in mvals:
        mvals[key] = {
                'packets': 0,
                'bytes': 0,
                'uniq_src_ips': set(),
                'uniq_dst_ips': set(),
                'uniq_src_asns': set()
            }

    mvals[key]['packets'] += r['packet_cnt']
    mvals[key]['bytes'] += (r['packet_cnt'] * r['ip_len'])
    mvals[key]['uniq_src_ips'].add(r['src_ip'])

    # TODO replicate prefix aggregation / sampling that is performed by
    # real-time plugin
    mvals[key]['uniq_dst_ips'].add(r['dst_ip'])
    mvals[key]['uniq_src_asns'].add(r['prefix2asn'])


def update_port_metric(mvals, r, is_src, is_pop):

    proto = r['protocol']
    if proto != 6 and proto != 17:
        return

    if is_src:
        key = r['src_port']
    else:
        key = r['dst_port']

    if is_pop and not is_popular_port(proto, key, is_src):
        return

    update_single_metric(mvals, key, r)

def update_ipproto_metric(mvals, r):

    key = r['protocol']
    update_single_metric(mvals, key, r)

def update_icmp_metric(mvals, r):
    if r['protocol'] != 1:
        return

    key = "%u:%u" % (r['src_port'], r['dst_port'])
    update_single_metric(mvals, key, r)

def update_asn_metric(mvals, r):
    key = r['prefix2asn']
    if key == 0:
        return
    update_single_metric(mvals, key, r)

def update_netacq_continent_metric(mvals, r):
    key = r['netacq_continent']
    update_single_metric(mvals, key, r)

def update_netacq_country_metric(mvals, r):
    key = r['netacq_country']
    update_single_metric(mvals, key, r)

def update_summary_metric(mvals, r):
    mvals['packets'] += r['packet_cnt']
    mvals['bytes'] += (r['packet_cnt'] * r['ip_len'])
    mvals['uniq_src_ips'].add(r['src_ip'])

    # TODO replicate prefix aggregation / sampling that is performed by
    # real-time plugin
    mvals['uniq_dst_ips'].add(r['dst_ip'])
    mvals['uniq_src_asns'].add(r['prefix2asn'])



def update_metric_counters(mmap, metrics, r):

    for m in metrics:
        if m == 'summary':
            update_summary_metric(mmap['summary'], r)
        if m == 'ipprotocol':
            update_ipproto_metric(mmap['ipprotocol'], r)

        if m == "tcpports" or m == "tcpports-pop":
            if r['protocol'] != 6:
                continue
            update_port_metric(mmap['tcp_src_ports'], r, True, (m == "tcpports-pop"))
            update_port_metric(mmap['tcp_dst_ports'], r, False, (m == "tcpports-pop"))

        if m == "udpports" or m == "udpports-pop":
            if r['protocol'] != 17:
                continue
            update_port_metric(mmap['udp_src_ports'], r, True, (m == "udpports-pop"))
            update_port_metric(mmap['udp_dst_ports'], r, False, (m == "udpports-pop"))

        if m == "icmp":
            if r['protocol'] != 1:
                continue
            update_icmp_metric(mmap['icmp'], r)

        if m == "asn":
            update_asn_metric(mmap['asn'], r)

        if m == "netacq":
            update_netacq_continent_metric(mmap['netacq_continents'], r)
            update_netacq_country_metric(mmap['netacq_countries'], r)

def output_counters(mmap):
    print("output_counters for %u", lastinterval)
    for metric, mvals in mmap.items():
        if metric == "summary":
            key = "overall"
            print("%u %s %s packets %lu" % (lastinterval, metric, key, mvals['packets']))
            print("%u %s %s bytes %lu" % (lastinterval, metric, key, mvals['bytes']))
            print("%u %s %s uniq_src_ips %lu" % (lastinterval, metric, key, len(mvals['uniq_src_ips'])))
            print("%u %s %s uniq_dst_ips %lu" % (lastinterval, metric, key, len(mvals['uniq_dst_ips'])))
            print("%u %s %s uniq_src_asns %lu" % (lastinterval, metric, key, len(mvals['uniq_src_asns'])))

            continue

        for key, counters in mvals.items():
            # TODO write output to kafka
            print("%u %s %s packets %lu" % (lastinterval, metric, key, counters['packets']))
            print("%u %s %s bytes %lu" % (lastinterval, metric, key, counters['bytes']))
            print("%u %s %s uniq_src_ips %lu" % (lastinterval, metric, key, len(counters['uniq_src_ips'])))
            print("%u %s %s uniq_dst_ips %lu" % (lastinterval, metric, key, len(counters['uniq_dst_ips'])))
            print("%u %s %s uniq_src_asns %lu" % (lastinterval, metric, key, len(counters['uniq_src_asns'])))


try:
    mode = sys.argv[2]
except:
    usage(sys.argv[0])

if mode not in ["unfiltered", "unfiltered-ipmeta", "nonspoofed", "unrouted-nonspoofed"]:
        print("Invalid filtering mode: %s" % (mode))
        usage(sys.argv[0])

if mode == "unfiltered":
    metrics = ['summary', 'ipprotocol', 'tcpports', 'udpports', 'icmp']
elif mode == "unfiltered-ipmeta":
    metrics = ['netacq', 'asn']
elif mode == "nonspoofed":
    metrics = ['summary', 'ipprotocol', 'netacq', 'tcpports-pop', 'icmp',
            'udpports-pop']
else:
    metrics = ['summary', 'ipprotocol']

lastinterval = 0
mmap = {}


try:
    with wandio.open(sys.argv[1]) as fh:
        avro_reader = reader(fh)
        for record in avro_reader:
            if lastinterval == 0:
                lastinterval = record['time']
                mmap = reset_counters(metrics)

            if should_ignore_record(record, mode):
                continue

            if record['time'] != lastinterval:
                output_counters(mmap)
                mmap = reset_counters(metrics)
                lastinterval = record["time"]

            update_metric_counters(mmap, metrics, record)

            #print(record)

except IOError as err:
    print(sys.argv[1])
    raise(err)

output_counters(mmap)

# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
