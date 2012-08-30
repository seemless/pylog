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
    for path in args:
        if os.path.isfile(path):
            counter = 0
            for e in gen_events(path):
                counter += 1
            print(counter)
def gen_flow(path):
    print("INFO: binary type is: %s" % "flow")
    args = ["flowd-reader",path]
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
        cleaned = None
        m = comp.match(line)
        if m is not None:
            event = m.groupdict()
            event['type'] = "flow"
            event["path"]=path
            cleaned = clean(event)
            
        p.stdout.flush()    
        yield cleaned    

def gen_events(path):

    method = get_bin_type(path)
    
    if os.path.isfile(path) and method is not None:
        return method(path)

def get_bin_type(path):
    ret = None
    for bin_type in bin_map:
        if path.endswith(bin_type) or bin_type in path:
            ret = bin_map[bin_type]
            break
        
    if ret is not None:
        print("INFO: binary type is: %s" % ret)
    else:
        print("WARN: binary type: %s not found by netpyfense" % path)
    return ret
        

def parse(path):
    events = []
    type_used = None
    for bin_type in bin_map:
        if path.endswith(bin_type) or bin_type in path:
            events = bin_map[bin_type](path,bin_type)
          
    print("netpyfense processed: ", path," events: ",len(events),"time: ", time.time())       
    return events

def gen_tcpdump(path):
    events = []
    print("INFO: log type is: %s" % "tcpdump")
    command = build_Tshark_command(path)
    args = shlex.split(command)
    p = subprocess.Popen(args,stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        splits = line.split("\t")
        event = dict(zip(field_names,splits))
        event['type'] = "tcpdump"         
        event['path'] = path
        
        p.stdout.flush()
        yield event

def build_Tshark_command(path):
   
    tail = " -e ".join(tshark_fields)
    head = "tshark -r %s -T fields -e " % (path)
    return head + tail

def gen_dragon(path):
    f = None
    cleaned = None
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
            event['type'] = "dragon"
            event['path'] = path
            cleaned = clean(event)
            
        f.flush()
        yield cleaned

#TODO: not done yet
def parse_snort_alert(path):
    
    event = None
    f = None
    
    #use gzip if it is compressed
    if path.endswith(".gz"):
        f = gzip.open(path)
    else:
        f = open(path)    
    
    for line in f:

        f.flush()
        yield event

def clean(event):
  
    try:
        event["epoch"] = carny.guess(event["date_time"])
    except Exception as e:
        print("event is mis-formatted")
        print(e)
        return None
      
    return event

bin_map = {#".flow":parse_flow_binary,
           ".flow":gen_flow,
           "dragon.log":gen_dragon,
           #"alert":parse_snort_alert,
           ".dmp":gen_tcpdump,
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