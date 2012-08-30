import re, os, sys, time, codecs, binascii
import carny

def test(args):
    gen_count = 0
    parse_count = 0
    
    for k in log_map:
        print(log_map[k]["method"])
            
def gen_events(path):
    log_dict = get_log_type(path)
            
    if os.path.isfile(path) and log_dict is not None:
        type_used = log_dict["type"]
        print("INFO: log type is: %s" % type_used)
        file_name = log_dict["file_name"]    
        method = log_dict["method"]
        if log_dict["multiline"]:
            
            return method(path, type_used, file_name)            
        else:
            pat = log_dict["pattern"]
            headers = log_dict["headers"]
            lines = gen_line(path)
            events = gen_dirty_event(lines, method, pat, headers)
            return gen_clean(events,type_used, file_name)    
                   
def gen_clean(events, used, name):
    '''Take in an event iterable, log type, and a file name
and use the latter two to enrich the event and give the event
an epoch timestamp'''

    for e in events:
        if e is not None:
            if used in unspecified:
                e["date_time"] = e["date_time"].strip()+" 2006"
            try:
                e["epoch"] = carny.guess(e["date_time"])
                                
            except Exception as e:
                print("ERROR: event is mis-formatted: %s" % str(e))
                yield None
            
            
            e['type'] = used
            e['file_name'] = name
            
            c = utf8_check(e)
            yield c   
            
def utf8_check(event):
    '''check an event to see if it has any nasty characters. '''
    has_hex = False
    for k,v in event.iteritems():
        try:
            
            str(v).encode(encoding='utf8')
        except Exception as e:
            print("WARN: found unsupported characters, tried reformatting")
            event[k] = reformat_content(v)
            has_hex = True
            
    event["has_hex"] = has_hex
    
    return event
            
def gen_dirty_event(lines, method, pattern, use_headers=None):
    '''abstaction generator that takes in lines of log files
their parsing method, the pattern to use, and the fields that
the line will be parsed into (if necessary). Methods supplied 
in the "method" argument must return a dictionary or None.'''
    
    for line in lines:
        yield method(line, pattern, use_headers)
    

def gen_line(path):
    '''Given a path, yeild each line for further processing. '''
    with open(path) as f:
        for line in f:
            yield line
    
def get_log_type(path):
    '''determine is pylog can parse the file given. There are strict
naming conventions used in pylog. Utilize the log_types() method to aid
in your use.'''
    log_dict = None
    file_name = path.split("/")[-1]
    
    #find the appropriate log definition for parsing
    for log_type in log_map:
        if log_type in file_name or log_type in file_name.split(".")[0]:
  
            log_dict = log_map[log_type]  
            log_dict['type'] = log_type
            #find it and get out before we duplicate (greedy)
            break
        
    #If we have a generic .log file (after specials have been checked)
    #select the appropriate generic log file parser
    if log_dict is None and file_name.endswith(".log"):
        log_dict = generic_logs['.log']
        log_dict['type'] = '.log' 
    
    #If we have the log type, add the file name
    if log_dict is not None:
        log_dict['file_name'] = file_name
    else:
        print("WARN: Log type %s not found, pylog is ignoring"%file_name)
    
    return log_dict


def parse_line(line,pattern, headers=None):
    ret = None
    
    if headers is not None:
        ret = _use_headers(line,pattern,headers)
        
    else:

        d = re.compile(pattern,re.VERBOSE).match(line)
        if d is not None:
            ret = d.groupdict()
            
    return ret

def _use_headers(line, pattern, headers):
    
    splits = line.split(pattern)
    
    if len(splits) >= 8 and not splits[7]:
        splits.remove('')

    if len(splits) != len(headers):
        print("Header mismatch, re-check logs: \n"+ line+ "\nheaders: "+str(headers))
        
    ret = dict(zip(headers,splits))
    try:
        ret["date_time"] = ret["date"]+" "+ret["time"]
    
    except Exception as e:
        print("_use_headers caught an exception while trying to munge date_time", e)

    return ret


def parse_ie_log(line,pattern,headers=None):
    headers1 = ["date_time","log_level","message"]
    headers2 = ["date_time","message"]
    
    splits = line.split(pattern)
    if len(splits) > 2:
        return dict(zip(headers1,splits))
    else:
        return dict(zip(headers2,splits))
    
def parse_unamed_log(line, pattern,headers=None):
    
    row = line.split(pattern)
    
    header1 = ["date_time","time","client_ip", "client_hostname",
               "partner_Name","server_hostname","server_ip",
               "recipient-address","event_id","msg_id","priority",
               "recipient_report_status","total_bytes","number_recipients",
               "origination_time","encryption","service_version",
               "linked_msg_id","message_subject","sender_address","additional"]
    
    ret = None

    if len(row) == len(header1):
        ret = dict(zip(header1,row))
        
    return ret

def parse_mail_log_line(line,pattern,headers=None):
    
    first_pass = parse_line(line,pattern,headers)
    pairs = first_pass['rest'].split(",")
    for pair in pairs:
        items = pair.split("=")
        first_pass[items[0].strip()] = items[1].strip()
    
    return first_pass

def parse_ossec_log(path, type_used, file_name):
    
    events = []
    with open(path) as f:
        for line in f:
            if "**" in line:
                event = dict()
                event["file_name"] = file_name
                event["type"] = type_used
                event["message"]= line
                
            else:
                m = re.match(r'(?P<date_time>^\d{,4}\s+\w+\s+\d\d\s+\d\d:\d\d:\d\d)',line)
                
                if m is not None:
                    event["date_time"] = m.groupdict()["date_time"]
                    
                event["message"] = event["message"] + line
                indx = line.find(":")
            
                if indx != -1:
                    
                    #these logs have dynamic fields in the format "<header> : <message>"
                    event[line[:indx].strip()] = line[indx+1:].strip()
                    
            if not line.strip():
                events.extend([event])
   
    return events

def log_types():
    first_keys = log_map.keys()
    keys = first_keys+ [".log"]
    return keys

def asciirepl(match):
  # replace the hexadecimal characters with ascii characters
    s = match.group()  
    return binascii.unhexlify(s)  

def reformat_content(data):
    p = re.compile(r'\\x(\w{2})')
    return p.sub(asciirepl, data)

unspecified = ["_maillog", "_messages", "_secure", "_last.log"]

win_log = {"pattern":"\t", 
           "method":parse_line, 
           "headers":["date","time","type","catetory","event_code","source_name","user","computer_name","description"],
           "multiline":False,
           }    
 
#TODO: handle the numeric logs better. 
generic_logs ={ ".log":
         {"pattern":"\t",
          "method":parse_unamed_log,
          "headers":None,
          "multiline":False,
          }
         } 

#The bread and butter of the script, contains regexes of the logs
#and which method to use to parse the log.
log_map = {
           "access_log":
           {"pattern":
                          r"""
                                  ^
                                  (?P<sip>[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})
                                  \s
                                  (?P<client_identity>[^ ]{1,})
                                  \s
                                  (?P<user_id>[^ ]{1,}|\-)
                                  \s
                                  \[(?P<date_time>[0-9]{2}\/[A-Za-z]{3}\/[0-9]{1,4}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}
                                  \s
                                  [+\-][0-9]{4})\]
                                  \s
                                  "(?P<http_request_type>[A-Z ]+)
                                  \s
                                  (?P<requested_resource>[^"]*)
                                  \s
                                  (?P<protocol>[^"]*)"
                                  \s
                                  (?P<response_code>[0-9]{3})
                                  \s
                                  ?(?P<bytes>[0-9]{1,}|\-)
                                  \s
                                  "(?P<referrer>[^"]*|\-)"
                                  \s
                                  "(?P<agent_string>[^"]+)"
                                  ?
                                  $
                          """,
           "method":parse_line,
           "headers":None,
           "multiline":False,
           },
            
            "error_log":
                       {"pattern":
                        r'''(?P<date_time>\[.*?\]) (?P<log_level>\[.*?\]) ?(?P<client_string>\[.*?\])? (?P<error_string>.*?$)''',
                        "method":parse_line,
                        "headers":None,
                        "multiline":False,
                       },
            "AppEvent":win_log,
            "SecEvent":win_log,
            "SysEvent":win_log,
            "win_user":
                     {"pattern":"::",
                      "method":parse_ie_log,
                      "headers":None,
                      "multiline":False,
                     },

            "_last.log":
                     {"pattern":
                      r'''^
                      (?P<command>\w+)
                      \s*
                      (?P<pid>\w+\d+)
                      \s*
                      (?P<source_name>(\w+[.]|\w+){1,})
                      \s*
                      (?P<date_time>\w+\s+\w+\s+\d{,2}\s+\d{,2}:\d{,2})
                      .*\(
                      (?P<duration>\d{,2}:\d{,2})
                      \)
                                                        
                      ''',
                      "method":parse_line,
                      "headers":None,
                      "multiline":False,
                     },
          "_maillog":
                     {"pattern":
                      r'''^
                      (?P<date_time>\w+\s+\d\s+\d\d:\d\d:\d\d)
                      \s*
                      (?P<folder>\w+)
                      \s*
                      (?P<action>\w+\[\d{1,}\])
                      :\s*
                      (?P<mail_id>\w+)
                      :
                      (?P<rest>.*$)
                      ''',
                      "method":parse_mail_log_line,
                      "headers":None,
                      "multiline":False,
                      },
           "_messages":
                     {"pattern":
                      r'''^
                      (?P<date_time>\w+\s+\d\s+\d\d:\d\d:\d\d)
                      \s*
                      (?P<folder>\w+)
                      \s*
                      (?P<service>.*)
                      :\s*
                      (?P<message>.*$)                     
                      ''',
                      "method":parse_line,
                      "headers":None,
                      "multiline":False,
                      },
            "_secure":
                      {"pattern":
                       r'''^
                       (?P<date_time>\w+\s+\d\s+\d{,2}:\d{,2}:\d{,2})
                       \s*
                       (?P<folder>\w+)
                       \s*
                       (?P<service>.*)
                       :\s*
                       (?P<message>.*$)                     
                       ''',
                       "method":parse_line,
                       "headers":None,
                       "multiline":False,
                       },
            ".xferlog":
                     {"pattern":
                      r'''^
                      (?P<date_time>\w+\s+\w+\s+\d{,2}\s+\d{,2}:\d{,2}:\d{,2}\s+\d{,4})
                      \s+
                      (?P<transfer_time>\d+)
                      \s+
                      (?P<remote_host>(\w+[.]|\w+){1,})
                      \s+
                      (?P<file_size>\d+)
                      \s+
                      (?P<file_name>.*?)
                      \s+
                      (?P<transfer_type>a|b)
                      \s+
                      (?P<special_action_flag>C|T|U|_)
                      \s+                      
                      (?P<direction>o|i|d )
                      \s+
                      (?P<access_mode>a|g|r)
                      \s+
                      (?P<username>.*?)
                      \s+  
                      (?P<service_name>.*?)
                      \s+                      
                      (?P<authentication_method>0|1)
                      \s+                        
                      (?P<authenticated_user_id>.*?)
                      \s+                    
                      (?P<completion_status>c|i$)
                      ''',
                      "method":parse_line,
                      "headers":None,
                      "multiline":False,
                      },
            "ossec.alert.log":
                    {"pattern":":",
                     "method":parse_ossec_log,
                     "headers":None,
                     "multiline":True,
                     },
        
          }

if __name__=="__main__": test(sys.argv[1:])