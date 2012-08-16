import sys, os, re, time
import pylog
import netpyfense
import carny
import pymongo

def main(args):

  print("Args: " + str(args[1:]))
  for arg in args[1:]:
    if os.path.isfile(arg):

        success = ingest(arg)
        print(success)
    else:
      print("Invalid path, first argument must be a file")
      sys.exit(0)



def ingest(path):
  time1 = time.time()
  print("ingesting: "+ path)
  
  events = pylog.parse_log(path)
      
  if not events:
    events = netpyfense.parse(path)
      
  print("number of events in: "+path, len(events))      

  #do all the databas insertion
  connection = pymongo.Connection('localhost', 27017)
  collection = connection["dapper"]["events"]  
  ids = collection.insert(events)
 
  time2 = time.time() - time1
  print("events ingested:",len(ids))
  print("Time to ingest",time2)  
  return len(ids)==len(events)
  
if __name__=="__main__":
  main(sys.argv)

