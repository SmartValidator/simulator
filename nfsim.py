#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)

debug=0
status_file='/tmp/smartvalidator_sim'
#db_host=''
#db_name=''
#db_user=''
#db_passwd=''
debug_fltr=['1.%d.%d.0/24'%(i,j) for i in range(0,255) for j in range(0,255)]


import sys
import os
import datetime
import tempfile
import subprocess

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


def write_status(filename, latest_point):
    # TODO
    pass

def read_status(filename):
    # TODO
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


def get_fltr_rpki():
    return debug_fltr


def get_fltr_resolved():
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


def run_nfdump(nfd_fn, fltr_fn):
    print('Running nfdump -r %s -f %s' % (nfd_fn, fltr_fn))
    p = subprocess.Popen(['nfdump', '-r', nfd_fn, '-f', fltr_fn], stdout=subprocess.PIPE)
    (output, err) = p.communicate()
    print(output)
    exit_code = process.wait()


def main():
    rootdir=sys.argv[1]
    files=filter_newer(sort_nfdump_files(find_files(rootdir)), read_status(status_file))
    print(str(files))
    with Filter(get_fltr_rpki()) as f:
        run_nfdump(files[0], f)





if __name__ == '__main__':
    main()

