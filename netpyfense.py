import time
import sys
import os
import subprocess
import re
import shlex
import gzip
import carny

def test(args):
    
    events = []
    print(args)
    if os.path.isfile(args[0]):
        parse(args[0])
        


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
            event['type'] = bin_type
            event["file_name"]=file_name
            cleaned = clean(event)
            events.extend([cleaned])
        p.stdout.flush()
    print("netpyfense processed: ", path," events: ",len(events))
    return events 

def parse_tcpdump(path, bin_type):
    events = []
    command = build_Tshark_command(path)
    file_name = path.split("/")[-1]
    args = shlex.split(command)
    p = subprocess.Popen(args,stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        splits = line.split("\t")
        event = dict(zip(field_names,splits))
        event['type'] = bin_type         
        event['file_name'] = file_name
        events.extend([event])
        p.stdout.flush()
    print("netpyfense processed: " , path, " events: ", len(events))
    return events

def build_Tshark_command(path):
   
    tail = " -e ".join(tshark_fields)
    head = "tshark -r %s -T fields -e " % (path)
    return head + tail

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
            event = dict(zip(headers,splits))
            event['type'] = bin_type
            event['file_name'] = path.split("/")[-1]
            cleaned = clean(event)
            events.extend([cleaned])
        f.flush()
    f.close()
    return events

#TODO: not done yet
def parse_snort_alert(path, bin_type):
    
    events =[]
    f = None
    
    #use gzip if it is compressed
    if path.endswith(".gz"):
        f = gzip.open(path)
    else:
        f = open(path)    
    
    for line in f:
        print(line)
        f.flush()

def clean(event):
  
    try:
        event["epoch"] = carny.guess(event["date_time"])
    except Exception as e:
        print("event is mis-formatted")
        print(e)
        return None
      
    return event

bin_map = {".flow":parse_flow_binary,
           "dragon.log":parse_dragon,
           "alert":parse_snort_alert,
           ".dmp":parse_tcpdump,
           }

tshark_fields = ['frame.time_epoch',
             'tcp.analysis.bytes_in_flight',
             'tcp.flags',
             'tcp.out_of_order',
             'tcp.reused_ports',
             'tcp.checksum',
             'tcp.checksum_bad',
             'tcp.checksum_good',
             'tcp.len',
             'tcp.hdr_len',
             'tcp.nxtseq',
             'tcp.options',
             'tcp.optins.scps',
             'tcp.wscale.multiplier',
             'tcp.wscale.shift',
             'tcp.pdu.size',
             'tcp.pdu.time',
             'tcp.proc.dstcmd',
             'tcp.proc.srccmd',
             'tcp.segment',
             'tcp.seq',
             'tcp.stream',
             'tcp.time_delta',
             'ip.proto',
             'ip.src',
             'ip.dst',
             'ip.ttl',
             'tcp.dstport',
             'tcp.srcport',
             'ip.checksum',
             'ip.checksum_good',
             'ip.checksum_bad',
             'ip.fragment.count',
             'ip.fragment.toolongfragment',
             'ip.hdr_len',
             ]
field_names = ['epoch',
             'bytes_in_flight',
             'flags',
             'out_of_order',
             'reused_ports',
             'tcp_checksum',
             'tcp_checksum_bad',
             'tcp_checksum_good',
             'tcp_len',
             'tcp_hdr_len',
             'nxtseq',
             'options',
             'options_scps',
             'wscale_multiplier',
             'wscale_shift',
             'pdu_size',
             'pdu_time',
             'proc_dstcmd',
             'proc_srccmd',
             'segment',
             'seq',
             'stream',
             'time_delta',
             'protocol',
             'sip',
             'dip',
             'ttl',
             'dport',
             'sport',
             'ip_checksum',
             'ip_checksum_good',
             'ip_checksum_bad',
             'ip_fragment_count',
             'ip_fragment_toolongfragment',
             'ip_hdr_len',
             ]

if __name__=="__main__": test(sys.argv[1:])