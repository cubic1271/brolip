#!/usr/bin/env python
import argparse
import os
import sys

from brolog.BroLogOptions import BroLogOptions
from brolog.BroLogManager import SimpleLogManager

def parse_args():
    parser = argparse.ArgumentParser(description='Quick bro-cut replacement')
    parser.add_argument('-v', default=False, action='store_true', dest='verbose', help='Explain what the script is doing')
    parser.add_argument('-f', default=None, action='store', dest='log', help='Log file to process')
    parser.add_argument('-d', default=False, action='store_true', dest='timestr', help='Display readable timestamps')
    parser.add_argument('fields', metavar='FIELDS', nargs='+', help='Fields to display')
    return parser.parse_args() 

if __name__ == '__main__':
    args = parse_args()
    if args.timestr:
        BroLogOptions.do_time_convert = True
    mgr = SimpleLogManager()
    mgr.load(args.log)
    target = args.fields

    for entry in mgr:
        map(lambda x: sys.stdout.write(str(entry[x]) + " "), target)
        print ""

