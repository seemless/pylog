import time
import sys
import os
import subprocess
import re

def main(args):
    
    events = []
    print(args)
    if os.path.isfile(args[0]):
        handle = parse_flow_binary(args[0]) 
#        if handle is not None:
 #           events = parse_flow_text(handle)
  #          os.remove(handle)
    return events

def parse(path):
    events = []
    for bin_type in bin_map:
        if path.endswith(bin_type):
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
    print("netpyfence processed: ", path," events: ",len(events))
    return events 

bin_map = {".flow":parse_flow_binary,
           }

if __name__=="__main__": main(sys.argv[1:])