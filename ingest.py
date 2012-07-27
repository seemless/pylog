import sys, os, re, time
import pylog
import netpyfense
import carny
#import pymongo

def main(args):

  print("Args: " + str(args[1:]))
  for arg in args[1:]:
    if os.path.isfile(arg):

        success = ingest(arg)

    else:
      print("Invalid path, first argument must be a file")
      sys.exit(0)



def ingest(path):
  time1 = time.time()
  print("ingesting: "+ path)
  events = None
  
  events = pylog.parse_log(path)
      
  if not events:
    events = netpyfense.parse(path)
    
  cleaned = []
  
  if events:
    for event in events:
      clean_event = clean(event)
      if clean_event is not None:
        cleaned.append(clean_event)
  print("number of events in: "+path, len(events))      
  print("numer of events cleaned: ",len(cleaned))  
  print("do the numbers match?: ", len(events) == len(cleaned))
  #print(events)
  db_objs = []  

      
  #last_index = len(objects)-1
  #clean up the list so I have no junk
  
  
  #objects[last_index] = objects[last_index].strip()
  #format the objects so I can insert them into the database
  #zipped = zip(headers,objects)
  #d = dict(zipped)
  #add to the list for a bulk insert
  #db_objs.append(d)
  
  #num_objs = len(db_objs)
  
  #connection = pymongo.Connection('localhost', 27017)
  #TODO: need to parameterize this call to get the collection we want based on file name
  #collection = connection.dapper["ips"]  
  #ids = collection.insert(db_objs)
  #count = collection.count()
  
  #return ids==num_objs and count == num_objs
  
  
  time2 = time.time() - time1
  print("Time to process",time2)  
  
  return True
  
def clean(event):
  
  try:
    event["epoch"] = carny.guess(event["date_time"])
  except Exception as e:
    print("event is mis-formatted")
    print(e)
    return None
  
  return event
  
if __name__=="__main__":
  main(sys.argv)

