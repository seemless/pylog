import time, re
#\d{,2}
#\d{,4}

time_patterns = {
                 #flow
                 r"\d{,4}-\d{,2}-\d{,2}T\d{,2}:\d{,2}:\d{,2}":"%Y-%m-%dT%H:%M:%S",
                 #AppEvent, SecEvent, SysEvent
                 r"\d{,2}\/\d{,2}\/\d{,4}\s+\d{,2}:\d{,2}:\d{,2}\s+[PM|AM]":"%m/%d/%Y %I:%M:%S %p",
                 #win_user.log, error_log, 
                 r"\w+\s+\w+\s+\d{,2}\s+\d{,2}:\d{,2}:\d{,2}\s+\d{,4}":"%a %b %d %H:%M:%S %Y",
                 #_maillog, _messages, _secure,
                 #(NB: the preceding log types do not include a year by default, 
                 # it must be added in post-processing)
                 r"\w+\s+\d{,2}\s+\d{,2}:\d{,2}:\d{,2}":"%b %d %H:%M:%S %Y", 
                 #{2006 Oct 01 18:06:11} ossec.alert.log,
                 r"\d{,4}\s+\w+\s+\d{,2}\s+\d{,2}:\d{,2}:\d{,2}":"%Y %b %d %H:%M:%S",
                 #{01/Oct/2006:17:52:01 -0400} access
                 r"\d{,2}\/\w+\/\d{,4}:\d{,2}:\d{,2}:\d{,2}\s+\-\d{,4}":"%d/%b/%Y:%H:%M:%S -0400",
                 #{2006-10-1       21:14:31} .log, dragon.log,
                 r"\d{,4}-\d{,2}-\d{,2}\s+\d{,2}:\d{,2}:\d{,2}":"%Y-%m-%d %H:%M:%S",
                 # _last.log, 
                 r"\w+\s+\w+\s+\d{,2}\s+\d{,2}:\d{,2}\s+\d{,4}":"%a %b %d %H:%M %Y",
}

def test():
    times =["2006-10-01T17:24:44",
            "9/16/2006 9:13:11 PM",
            "Sun Oct  1 22:38:22 2006",
            "Mon Oct 02 13:27:23 2006",
            "Oct  1 22:46:50 2006",
            "01/Oct/2006:17:52:01 -0400",
            "2006-10-1       21:14:31",
            "2006 Oct 01 18:06:11",
            ]
    epochs = []
    
    for t in times:
        epoch = guess(t)
        if epoch is not None:
            epochs.append(epoch)
    
    print(len(epochs))

def guess(date_time_str):
    
    for pat in time_patterns:
        m = re.compile(pat).match(date_time_str)
        if m is not None:
            fmt = time_patterns[pat]
            epoch = get_epoch(date_time_str,fmt)
            return epoch
        
def get_epoch(date_time_str, fmt):
    struct = time.strptime(date_time_str,fmt)
    #make your time
    epoch = time.mktime(struct)
    return epoch

def get_keys():
    return time_patterns.keys()

def get_all():
    return time_patterns


if __name__=="__main__":
    test()