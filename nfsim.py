#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)

debug=1
status_file='/tmp/smartvalidator_sim'
#db_host=''
#db_name=''
#db_user=''
#db_passwd=''
debug_fltr=['217.%d.%d.0/24'%(i,i) for i in range(0,255)]


import sys
import os
import datetime
import tempfile
import subprocess
import getopt

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


def get_fltr_saved_conflicts():
    return debug_fltr


def get_fltr_raw_rpki():
    return debug_fltr


def get_fltr_resolved_conflicts():
    return debug_fltr


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
    for l in stdout:
        print(l.decode('ascii').strip())

    # TODO: generate result to be written to DB
    return None


def run_nfdump(nfd_fn, fltr_fn):
    dbg('Running nfdump -r %s -f %s' % (nfd_fn, fltr_fn))
    p = subprocess.Popen(['nfdump', '-r', nfd_fn, '-f', fltr_fn], stdout=subprocess.PIPE)
    res = process_nfdump_output(p.stdout)
    exit_code = p.wait()
    return res


def main():
    def usage():
        print("""SmartValidator NetFlow simulator
    %s <-d <dir>> [-hsre]
        -d | --dir <nfdump data directory>
        -h | --help
        -s | --saved -- filters traffic for salvaged invalid ROAs
        -r | --rpki -- filters traffic dropped by "raw" RPKI
        -e | --resolved -- filters traffic dropped in Smart mode
""" % sys.argv[0])

    rootdir=None
    fltr=None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hd:sre", ["help", "dir=", "saved", "rpki", "resolved"])
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
        elif o in ("-r", "--rpki"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_raw_rpki()
        elif o in ("-e", "--resolved"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_resolved_conflicts()
        else:
            assert False, "unhandled option"

    assert rootdir, "missing root directory"
    assert fltr, "missing filter option"


    files=filter_newer(sort_nfdump_files(find_files(rootdir)), read_status())
    with Filter(fltr) as fl:
        for fn in files:
            res = run_nfdump(fn, fl)
            # TODO: write res to DB
        write_status(decode_nfdump_time(files[-1]))


if __name__ == '__main__':
    main()

