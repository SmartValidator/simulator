#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)


debug=0
status_file='/tmp/smartvalidator_sim'

ports = [80,443,25,110,143,53]
protocols = [6,17]

import sys
import os
import datetime
import tempfile
import subprocess
import getopt
import csv
import iptree
import ipaddress


def dbg(text):
    if debug:
        print(text)


def decode_nfdump_time(filename):
    """
    Implement & expect NFSen SUBDIRLAYOUT 1
    example: /srv/nfsen/profiles-data/live/homer/2017/12/16/nfcapd.201712160900
    """
    fnc = filename.split(os.path.sep)
    base, time = fnc[-1].split('.')

    if base != 'nfcapd':
        raise Exception("Filename check failed. No basename found.")

    return datetime.datetime(int(fnc[-4]), int(fnc[-3]), int(fnc[-2]), int(time[8:10]), int(time[10:]))


def sort_nfdump_files(files):
    return sorted(list(files), key=decode_nfdump_time)


def filter_newer(files, latest_point):
    """
        files is list of filenames
        latest_point is datetime.datetime obj
    """
    return [f for f in files if decode_nfdump_time(f) > latest_point]


def write_status(latest_point, filename=status_file):
    with open(filename, 'w') as fh:
        fh.write(str(int(latest_point.timestamp())))

def read_status(filename=status_file):
    try:
        with open(filename, 'r') as fh:
            l = fh.readline()
            ts = datetime.datetime.fromtimestamp(int(l))
            dbg("timestamp read=%s" % str(ts))
            return ts
    except:
        pass
    return datetime.datetime(1970,1,1,0,0)


def find_files(rootdir):
    for root, dirs, files in os.walk(rootdir):
        for name in files:
            fn = os.path.abspath(os.path.join(root, name))
            try:
                decode_nfdump_time(fn)
            except:
                pass
            else:
                yield fn


def read_filter(fltrfn):
    t = iptree.IPLookupTree(ipv6=False)
    with open(fltrfn, 'r') as fh:
        for l in fh:
            try:
                ipa = ipaddress.IPv4Address(l)
                t.add(ipa, True)
            except:
                dbg("Ignoring line %s" % l)
                pass
    return t


def process_nfdump_output(stdout):
    def splitipport(ipport):
        g=ipport.split(':')
        if len(g) == 2:
            return (g[0], int(g[1]))
        else:
            raise Exception("Can not split address and port %s" % ipport)

    def parseline(l):
        try:
            s = l.split()
            dt = datetime.datetime.strptime('%s %s'%(s[0], s[1]), '%Y-%m-%d %H:%M:%S.%f')
            (src, srcport) = splitipport(s[4])
            (dst, dstport) = splitipport(s[6])
            return (dt, float(s[2]), int(s[3]), src, srcport, dst, dstport, int(s[7]), int(s[8]), int(s[9]))
        except:
            return None
        # (date, duration, protocol, src, srcport, dst, dstport, packets, bytes, flows)

    for l in stdout:
        #print(l.decode('ascii').strip())
        r = parseline(l.decode('ascii').strip())
        if r:
            yield r


def process_records(records, fltr, srcfilename, outdir):
    header = ['date', 'duration', 'protocol', 'src', 'srcport', 'dst', 'dstport', 'packets', 'bytes', 'flows']

    proto_packets = {p:0 for p in protocols}
    proto_packets[None] = 0
    proto_bytes = {p:0 for p in protocols}
    proto_bytes[None] = 0

    port_packets = {p:0 for p in ports}
    port_packets[None] = 0
    port_bytes = {p:0 for p in ports}
    port_bytes[None] = 0

    def update(table, key, value):
        if key in table:
            table[key] += value
        else:
            table[None] += value

    ofh = None
    ofw = None
    if outdir:
        ofh = open(os.path.join(outdir, '%s.csv' % srcfilename), 'w')
        ofw = csv.writer(ofh, quoting=csv.QUOTE_MINIMAL)
        ofw.writerow(header)

    for r in records:
        if not fltr.lookupBest(r[3]) and not fltr.lookupBest(r[5]):
            continue

        # write CSV, compute summaries
        if ofw:
            ofw.writerow(r)

        update(proto_packets, r[2], r[7])
        update(proto_bytes, r[2], r[8])

        update(port_packets, r[4], r[7])
        update(port_bytes, r[4], r[8])
        update(port_packets, r[6], r[7])
        update(port_bytes, r[6], r[8])

    if ofh:
        ofh.close()

    # write report (now stdout, future to DB)
    print("proto_packets")
    print(str(proto_packets))
    print("proto_bytes")
    print(str(proto_bytes))
    print("port_packets")
    print(str(port_packets))
    print("port_bytes")
    print(str(port_bytes))


def run_nfdump(nfd_fn, fltr_fn):
    dbg('Running nfdump -N -r %s -f %s' % (nfd_fn, fltr_fn))
    p = subprocess.Popen(['nfdump', '-N', '-r', nfd_fn, '-f', fltr_fn], stdout=subprocess.PIPE)
    res = process_nfdump_output(p.stdout)
    return (res, p)


def main():
    dbselect("select * from netflows;")

    def usage():
        print("""SmartValidator NetFlow simulator
    %s <-d <dir>> [-hsre]
        -d | --dir <nfdump data directory>
        -f | --filter <IP prefix list>
        -h | --help
        -s | --saved -- filters traffic for salvaged invalid ROAs
        -r | --rpki -- filters traffic dropped by "raw" RPKI
        -e | --resolved -- filters traffic dropped in Smart mode
        -o | --outdir <CSV out directory>
""" % sys.argv[0])

    rootdir = None
    fltrfn = None
    outdir = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:sreo:f:", ["help", "dir=", "outdir=", "filter="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-d", "--dir"):
            rootdir = a
        elif o in ("-o", "--outdir"):
            outdir = a
        elif o in ("-f", "--filter" ):
            filterfn = a
        else:
            assert False, "unhandled option"

    assert rootdir, "missing root directory"
    assert fltr, "missing filter option"

    fltr = read_filter(fltrfn)
    files = filter_newer(sort_nfdump_files(find_files(rootdir)), read_status())
    for fn in files:
        (res, proc) = run_nfdump(fn)
        process_records(res, fltr, os.path.split(fn)[-1], outdir)
        nfdump_exit_code = proc.wait()
        dbg('nfdump exited with code %d'%nfdump_exit_code)

        write_status(decode_nfdump_time(files[-1]))


if __name__ == '__main__':
    main()

