#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)

import password

debug=0
status_file='/tmp/smartvalidator_sim'
db_host=password.db_host
db_name=password.db_name
db_user=password.db_user
db_passwd=password.db_passwd
#debug_fltr=['217.%d.%d.0/24'%(i,i) for i in range(0,255)]
debug_fltr=['217.31.48.0/20']


import sys
import os
import datetime
import tempfile
import subprocess
import getopt
import psycopg2

def dbg(text):
    if debug:
        print(text)


def dbconn():
    return 'host=%s dbname=%s user=%s password=%s' % (db_host, db_name, db_user, db_passwd)


def dbselect(select):
    conn = psycopg2.connect(dbconn())
    cur = conn.cursor()
    cur.execute(select)
    for r in cur:
        yield r

    # conn.commit()
    cur.close()
    conn.close() 


def get_fltr_saved_conflicts():
    # filtered / whitelisted from validated_roas (difference of our result from RIPE)
    # return list(dbselect("SELECT prefix FROM validated_roas WHERE filtered = 't';"))
    return debug_fltr


def get_fltr_raw_rpki():
    # conflicts found by conflict seeker (RIPE validator result)
    return debug_fltr


def get_fltr_resolved_conflicts():
    # not filtered / whitelisted from validated_roas (our result)
    # return list(dbselect("SELECT prefix FROM validated_roas WHERE filtered = 'f' and whitelisted = 'f';"))
    return debug_fltr


#def insert_records(filter_type, records):
#    """ Using table netflows
#    filter_type: 1 = fltr_resolved_conflicts (our output)
#                 2 = fltr_raw_rpki
#                 3 = fltr_saved_conflicts (difference)
#
#    records: list of tuples:
#        (date, duration, protocol src, srcport, dst, dstport, packets, bytes, flows)
#    """
#    
#    conn = psycopg2.connect(dbconn())
#    cur = conn.cursor()
# 
#    i = 0
#    for r in records:
#        #dbg("inserting %s" % str(r))
#        cur.execute("INSERT INTO netflows (date, duration, protocol, src, srcport, dst, dstport, packets, bytes, flows, filter_type) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", (r + (filter_type,)))
#        i+=1
#        if (i % 1000) == 0:
#            conn.commit()
#    conn.commit()
#    cur.close()
#    conn.close()


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



class Filter:
    def __init__(self, prefixes, ports=None):
        self.prefixes = prefixes
        self.ports = ports

    def __enter__(self):
        fhos, fn = tempfile.mkstemp()
        with open(fhos, 'w') as fh:
            self.fn = fn
            if self.prefixes:
                fh.write('(')
                for p in self.prefixes[:-1]:
                    fh.write('net %s or \n' % p)
                fh.write('net %s)\n' % self.prefixes[-1])
            if self.prefixes and self.ports:
                fh.write(' and ')
            if self.ports:
                fh.write('(')
                for p in self.ports[:-1]:
                    fh.write('port %s or \n' % p)
                fh.write('port %s)\n' % self.ports[-1])

        return self.fn

    def __exit__(self, etype, evalue, etraceback):
        os.remove(self.fn)


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


def process_records(filter_type, records, srcfilename, outdir):
    header = ['date', 'duration', 'protocol', 'src', 'srcport', 'dst', 'dstport', 'packets', 'bytes', 'flows']
    with open(os.path.join(outdir, '%s.csv' % srcfilename), 'w') as ofh:
        ofw = csv.writer(ofh, quoting=csv.QUOTE_MINIMAL)
        ofw.writerow(header)
        for r in records:
            # write CSV, compute summaries?
            ofw.writerow(r)


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
        -h | --help
        -s | --saved -- filters traffic for salvaged invalid ROAs
        -r | --rpki -- filters traffic dropped by "raw" RPKI
        -e | --resolved -- filters traffic dropped in Smart mode
""" % sys.argv[0])

    rootdir = None
    fltr = None
    filter_type = 0
    outdir = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:sreo:", ["help", "dir=", "saved", "rpki", "resolved", "outdir="])
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
        elif o in ("-s", "--saved"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_saved_conflicts()
            filter_type = 3
        elif o in ("-r", "--rpki"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_raw_rpki()
            filter_type = 2
        elif o in ("-e", "--resolved"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_resolved_conflicts()
            filter_type = 1
        elif o in ("-o", "--outdir"):
            outdir = a
        else:
            assert False, "unhandled option"

    assert rootdir, "missing root directory"
    assert fltr, "missing filter option"


    files=filter_newer(sort_nfdump_files(find_files(rootdir)), read_status())
    with Filter(fltr) as fl:
        for fn in files:
            (res, proc) = run_nfdump(fn, fl)
            #insert_records(filter_type, res)
            process_records(filter_type, res, os.path.split(fn)[-1], outdir)
            nfdump_exit_code = proc.wait()
            dbg('nfdump exited with code %d'%nfdump_exit_code)

        write_status(decode_nfdump_time(files[-1]))


if __name__ == '__main__':
    main()

