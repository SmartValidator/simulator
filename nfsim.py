#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)


debug=1
status_file='/tmp/smartvalidator_sim'
lock_file='/tmp/smartvalidator_lock'

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
import multiprocessing
import os.path

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

    # (Y, M, D, H, M)
    return datetime.datetime(int(time[0:4]), int(time[4:6]), int(time[6:8]), int(time[8:10]), int(time[10:]))


def decode_hostname(filename):
    fnc = filename.split(os.path.sep)
    return fnc[-5]


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
                ipa = ipaddress.IPv4Network(l.strip())
                t.add(ipa, True)
            except:
                print("Ignoring line %s" % l)
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

    drop_proto_packets = {p:0 for p in (protocols + [None])}
    accept_proto_packets = {p:0 for p in (protocols + [None])}
    drop_proto_bytes = {p:0 for p in (protocols + [None])}
    accept_proto_bytes = {p:0 for p in (protocols + [None])}

    drop_port_packets = {p:0 for p in (ports + [None])}
    accept_port_packets = {p:0 for p in (ports + [None])}
    drop_port_bytes = {p:0 for p in (ports + [None])}
    accept_port_bytes = {p:0 for p in (ports + [None])}

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
        if fltr.lookupBest(r[3]) and not fltr.lookupBest(r[5]): # ROV is dropping the flow
            if ofw:
                ofw.writerow(r)

            update(drop_proto_packets, r[2], r[7])
            update(drop_proto_bytes, r[2], r[8])

            update(drop_port_packets, r[4], r[7])
            update(drop_port_bytes, r[4], r[8])

            if r[4] != r[6]:
                update(drop_port_packets, r[6], r[7])
                update(drop_port_bytes, r[6], r[8])
        else: # ROV accepts the flow
            update(accept_proto_packets, r[2], r[7])
            update(accept_proto_bytes, r[2], r[8])

            update(accept_port_packets, r[4], r[7])
            update(accept_port_bytes, r[4], r[8])

            if r[4] != r[6]:
                update(accept_port_packets, r[6], r[7])
                update(accept_port_bytes, r[6], r[8])


    if ofh:
        ofh.close()

    return (decode_nfdump_time(srcfilename), drop_proto_packets, drop_proto_bytes, drop_port_packets, drop_port_bytes, accept_proto_packets, accept_proto_bytes, accept_port_packets, accept_port_bytes)

def decode_header():
    return ["time", "router"]+["drop_packets_proto_%d" % p for p in protocols]+["drop_packets_proto_other"]+["drop_bytes_proto_%d" % p for p in protocols]+["drop_bytes_proto_other"]+["drop_packets_port_%d" % p for p in ports]+["drop_packets_port_other"]+["drop_bytes_port_%d" % p for p in ports]+["drop_bytes_port_other"]+["accept_packets_proto_%d" % p for p in protocols]+["accept_packets_proto_other"]+["accept_bytes_proto_%d" % p for p in protocols]+["accept_bytes_proto_other"]+["accept_packets_port_%d" % p for p in ports]+["accept_packets_port_other"]+["accept_bytes_port_%d" % p for p in ports]+["accept_bytes_port_other"]



def decode_rep(report, filename):
    (time, drop_proto_packets, drop_proto_bytes, drop_port_packets, drop_port_bytes, accept_proto_packets, accept_proto_bytes, accept_port_packets, accept_port_bytes) = report
    return [time, decode_hostname(filename)]+[drop_proto_packets[k] for k in (protocols + [None])]+[drop_proto_bytes[k] for k in (protocols + [None])]+[drop_port_packets[k] for k in (ports + [None])]+[drop_port_bytes[k] for k in (ports + [None])]+[accept_proto_packets[k] for k in (protocols + [None])]+[accept_proto_bytes[k] for k in (protocols + [None])]+[accept_port_packets[k] for k in (ports + [None])]+[accept_port_bytes[k] for k in (ports + [None])]


def run_nfdump(nfd_fn):
    dbg('Running nfdump -N -r %s' % (nfd_fn))
    p = subprocess.Popen(['nfdump', '-N', '-r', nfd_fn], stdout=subprocess.PIPE)
    res = process_nfdump_output(p.stdout)
    return (res, p)


def worker(params):
    try:
        (fn, fltr, outdir) = params
        dbg("worker started with %s"%fn)
        (res, proc) = run_nfdump(fn)
        rep = process_records(res, fltr, os.path.split(fn)[-1], outdir)
        nfdump_exit_code = proc.wait()
        dbg('nfdump exited with code %d'%nfdump_exit_code)

        write_status(decode_nfdump_time(fn))

        ret = decode_rep(rep, fn)
        dbg("return from worker: %s"%ret)
        return ret
    except Exception as e:
        print("Worker failed: %s"%e)
        raise


def run_sim(rootdir, fltrfn, outdir, reportfn):
    fltr = read_filter(fltrfn)
    files = filter_newer(sort_nfdump_files(find_files(rootdir)), read_status())
    write_header = True
    try:
        if os.stat(reportfn).st_size > 0:
            write_header = False
    except:
        pass

    p = multiprocessing.Pool(processes=4)
    with open(reportfn, 'a') as reportfh:
        reportcsv = csv.writer(reportfh, quoting=csv.QUOTE_MINIMAL)
        if write_header:
            reportcsv.writerow(decode_header())

        for res in p.map(worker, list(zip(files, [fltr]*len(files), [outdir]*len(files)))):
        #for param in list(zip(files, [fltr]*len(files), [outdir]*len(files))):
        #    res = worker(param)

            dbg("writing result from map(workers): %s"%str(res))
            reportcsv.writerow(res)

    print("Finished files:")
    for fn in files:
        print(fn)



def check_lock():
    if not os.path.isfile(lock_file):
        with open(lock_file, 'w') as lf:
            lf.write(str(os.getpid()))
        return True
    else:
        return False


def release_lock():
    os.remove(lock_file)


def main():
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
        -p | --reportfile <CSV report file>
""" % sys.argv[0])

    rootdir = None
    fltrfn = None
    outdir = None
    reportfn = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:sreo:f:p:", ["help", "dir=", "outdir=", "filter=", "reportfile="])
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
            fltrfn = a
        elif o in ("-p", "--reportfile"):
            reportfn = a
        else:
            assert False, "unhandled option"

    assert rootdir, "missing root directory"
    assert fltrfn, "missing filter option"
    assert reportfn, "missing report file name"

    if check_lock():
        run_sim(rootdir, fltrfn, outdir, reportfn)
        release_lock()


if __name__ == '__main__':
    main()

