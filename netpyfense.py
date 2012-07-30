import time
import sys
import os
import subprocess
import re
import gzip

def test(args):
    
    events = []
    print(args)
    if os.path.isfile(args[0]):
        events = parse(args[0])
        print(len(events))
    sys.exit(0)
        


def parse(path):
    events = []
    for bin_type in bin_map:
        if path.endswith(bin_type) or bin_type in path:
            events = bin_map[bin_type](path,bin_type)

    return events

def parse_flow_binary(path,bin_type):
    events = []
    args = ["flowd-reader",path]
    file_name = path.split("/")[-1]
    pat = r'''^
            (?P<type>\w+)
            \s+recv_time\s+
            (?P<date_time>\d{,4}-\d\d-\d\dT\d\d:\d\d:\d\d)
            \s+proto\s+
            (?P<protocol>\d{,2})
            \s+tcpflags\s+
            (?P<flags>\w+)
            \s+tos\s+
            (?P<tos>)\d+?
            \s+agent\s+\[
            (?P<agent>[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})
            \]\s+src\s+\[
            (?P<sip>[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})
            \]:
            (?P<sport>\d+)
            \s+dst\s+\[
            (?P<dip>[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})
            \]:
            (?P<dport>\d+)
            \s+packets\s+
            (?P<packets>\d+)
            \s+octets\s+
            (?P<octets>\d+)
    '''    
    comp = re.compile(pat,re.VERBOSE)    
    p = subprocess.Popen(args,stdout=subprocess.PIPE)


    for line in p.stdout.readlines():
        m = comp.match(line)
        if m is not None:
            event = m.groupdict()

            event["file_name"]=file_name
            events.append(event)
        p.stdout.flush()
    print("netpyfense processed: ", path," events: ",len(events))
    return events 

def parse_dragon(path, bin_type):
    events =[]
    f = None
    
    #use gzip if it is compressed
    if path.endswith(".gz"):
        f = gzip.open(path)
    else:
        f = open(path)
   
    headers = ['date_time','sensor_id','protocol_name',
               'sip','dip','sport','dport','additional_1',
               'additional_2','protocol','event','blank']    
    
    for line in f:
        splits = line.split("|")
        #defense guard in case there is a rogue event
        if len(splits) != 13:
            try:
                print(path,splits)
                raise IndexError("out of bounds")
            finally:
                sys.exit(-1)
        
        else:
            events.extend([dict(zip(headers,splits))])
        f.flush()
    f.close()
    return events

bin_map = {".flow":parse_flow_binary,
           "dragon.log":parse_dragon,
           }

if __name__=="__main__": test(sys.argv[1:])