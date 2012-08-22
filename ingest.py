import sys, os, re, time
import pylog
import netpyfense
import carny
import pymongo

def main(args):

  print("INFO: Args: " + str(args[1:]))
  for path in args[1:]:

      success = ingest(path)
      print(success)
      

def ingest(path):
  time1 = time.time()
  print("INFO: ingesting file: "+ path)
  counter = 0 
  gen = pylog.gen_events(path)
  if gen:
    for e in gen:
      counter += 1
  else:
    gen = netpyfense.gen_events(path)
  
  if gen:
    for e in gen:
      counter += 1
      
  time2 = time.time()
  delta = time2-time1
  print ("INFO: there were %d events in %s and took %d seconds to parse" % (counter, path, delta))    
    #events = netpyfense.parse(path)      
  
  #if events:
    
    #try:
      #connection = pymongo.Connection('localhost', 27017)
      #collection = connection["dapper"]["events"]  
    #except Exception as e:
      #print("ERROR: in ingest database connection")
      #print(e)
      #return False    
    
    ##do all the databas insertion
    #try:
      #print("INFO: Inserting events into db: ", len(events))
      #ids = collection.insert(events)
    #except Exception as e:
      #print("ERROR: in database insertion at file:", path)
      #print(e)
      #return False
    
    #time2 = time.time()
    #delta = time2 - time1
    #print("INFO: events ingested into database: ",len(ids))
    #print("INFO: ingest processing time: ",delta) 
    #print("INFO: ingest time range: ",time1," - ",time2)
    #return len(ids)==len(events)
  #else:
  return False
  
if __name__=="__main__":
  main(sys.argv)

