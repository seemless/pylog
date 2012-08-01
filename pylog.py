import re
import carny

def parse_log(path):
    events = []    
    
    log_dict = None
    type_used = None
    file_name = path.split("/")[-1]
    print(file_name)
    
    #find the appropriate log definition for parsing
    for log_type in log_map:
        if log_type in file_name or log_type in file_name.split(".")[0]:

            log_dict = log_map[log_type]  
            type_used = log_type
            #find it and get out before we duplicate (greedy)
            break
        
    #If we have a generic .log file (after specials have been checked)
    #select the appropriate generic log file parser
    if log_dict is None and file_name.endswith(".log"):
        log_dict = generic_logs['.log']
        type_used = '.log'
        
    
    if log_dict is not None:
        
        method = log_dict["method"]
        pattern = log_dict["pattern"]
        headers = log_dict["headers"]
        multiline = log_dict["multiline"]

        #If the event is multilined, we can't generically parse through the
        #file line by line. Therefore, we have to delegate the whole file to a
        #new method for parsing.
        if multiline:
            events = method(path, type_used, file_name)
            
        else:
            #it has a standard event every line, parse it
            with open(path) as f:
                for line in f:     
                    event = method(line,pattern,headers)
                    if event is not None:
                        event["type"] = type_used
                        event["file_name"] = file_name
                        #some logs don't record year data, add it. 
                        if type_used in unspecified:
                            event["date_time"] = event["date_time"].strip()+" 2006"
                        cleaned = clean(event)
                        events.extend([cleaned])
    else:
        print("Log type not found. Pylog is ignoring. \n"+ path)
    return events

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


def parse_win_event_line(line,pattern):
    header =[]
    row = line.split(pattern)
    
    return dict(zip(headers,row))

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
                events.append(event)

    return events

def clean(event):
  
    try:
        event["epoch"] = carny.guess(event["date_time"])
    except Exception as e:
        print("event is mis-formatted")
        print(e)
        return None
    
    return event

def log_types():
    first_keys = log_map.keys()
    keys = first_keys+ [".log"]
    return keys

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