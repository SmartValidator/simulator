#!/usr/bin/python3

# SmartValidator - simulator component
# by Tomas Hlavacek (tmshlvck@gmail.com)

import password

debug=0
db_host=password.db_host
db_name=password.db_name
db_user=password.db_user
db_passwd=password.db_passwd

import sys
import os
import datetime
import tempfile
import subprocess
import getopt
import psycopg2
import csv

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
    for r in dbselect("select prefix from announcements inner join validated_roas_verified_announcements as o on announcements.id = verified_announcement_id where route_validity > 0 and not exists ( select verified_announcement_id from validated_roas_verified_announcements where route_validity = 0 and verified_announcement_id = o.verified_announcement_id ) and family(prefix) = 4 group by prefix;"):
        yield r


def get_fltr_resolved_conflicts():
    # not filtered / whitelisted from validated_roas (our result)
    # return list(dbselect("SELECT prefix FROM validated_roas WHERE filtered = 'f' and whitelisted = 'f';"))
    return debug_fltr


def main():
    def usage():
        print("""SmartValidator NetFlow simulator
    %s <-d <dir>> [-hsre]
        -h | --help
        -s | --saved -- filters traffic for salvaged invalid ROAs
        -r | --rpki -- filters traffic dropped by "raw" RPKI
        -e | --resolved -- filters traffic dropped in Smart mode
        -o | --outfile <out file>
""" % sys.argv[0])


    outfn = None
    fltr = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hsreo:", ["help", "saved", "rpki", "resolved", "outfile="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s", "--saved"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_saved_conflicts()
        elif o in ("-r", "--rpki"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_raw_rpki()
        elif o in ("-e", "--resolved"):
            assert fltr == None, "multiple filtering options"
            fltr = get_fltr_resolved_conflicts()
        elif o in ("-o", "--outfile"):
            outfn = a
        else:
            assert False, "unhandled option"

    assert fltr, "missing filter option"
    assert outfn, "missing out file"

    with open(outfn, "w") as outfh:
        for fr in fltr:
            outfh.write("%s\n"%fr)


if __name__ == '__main__':
    main()

