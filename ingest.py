import sys, os, re, time
import pylog
import netpyfense
import carny
import pymongo

def main(args):

  print("INFO: Args: " + str(args[1:]))
  for path in args[1:]:

    if os.path.isfile(path):

        success = ingest(path)
        print(success)
    else:
      print("ERROR: Invalid path, first argument must be a file", arg)
      sys.exit(0)



def ingest(path):
  time1 = time.time()
  print("INFO: ingesting file: "+ path)
  
  events = pylog.parse_log(path)
      
  if not events:
    events = netpyfense.parse(path)      
  
  if events:
    
    try:
      connection = pymongo.Connection('localhost', 27017)
      collection = connection["dapper"]["events"]  
    except Exception as e:
      print("ERROR: in ingest database connection")
      print(e)
      return False    
    
    #do all the databas insertion
    try:
      print("INFO: Inserting events into db: ", len(events))
      ids = collection.insert(events)
    except Exception as e:
      print("ERROR: in database insertion at file:", path)
      print(e)
      return False
    
    time2 = time.time()
    delta = time2 - time1
    print("INFO: events ingested into database: ",len(ids))
    print("INFO: ingest processing time: ",delta) 
    print("INFO: ingest time range: ",time1," - ",time2)
    return len(ids)==len(events)
  else:
    return False
  
if __name__=="__main__":
  main(sys.argv)

