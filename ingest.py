import sys, os, re, time
import pylog
import netpyfense
import carny
import pymongo

def main(args):

  print("INFO: Args: " + str(args[1:]))
  for path in args[1:]:
    if "index" not in path:
      file_paths = gen_paths(path)
      for p in file_paths:
        if p is not None:
          success = ingest(p)
          print(success)
    else:
      print("WARN: ignoring %s because it has an 'index' in it" % path)

def gen_paths(path):
  #index files are htmls that are used for quick fs browsing,
  #they offer no information for the data set.
  if os.path.isdir(path):
    for path, dirlist, filelist in os.walk(path):
      for name in filelist:
        if "index" not in name:
          yield os.path.join(path,name)
        else:
          print("WARN: ignoring %s because it has an 'index' in it" % path)
  
  else:
    yield path

    
def ingest(path):
  time1 = time.time()
  print("INFO: ingesting file: "+ path)
  
  parsers = [pylog, netpyfense]
  counter = 0 
  collection = None
  ids = []

  for p in parsers:
    gen = p.gen_events(path)
    if gen:
      #Make all the connections once
      try:
        connection = pymongo.Connection('localhost', 27017)
        collection = connection["dapper"]["events"]  
      except Exception as e:
        print("ERROR: in ingest database connection")
        print(e)
        return False          
    
      for event in gen:
        #Make the database insertion
        if event is not None:
          try:
            ids.extend([collection.insert(event)])
            counter += 1
          except Exception as e:
            print("ERROR: in database insertion at file: %s" % path)
            print("ERROR: malformed event: %s" % str(event))
            print(e)
            return False          
        
      break

  time2 = time.time()
  delta = time2-time1
  print ("INFO: there were %d events in %s and the file took %d seconds to parse" % (counter, path, delta))      
  print("INFO: events ingested into database: %d" % len(ids))
  print("INFO: ingest processing time: %d " % delta) 
  print("INFO: ingest time range: %d - %d" %(time1,time2))
  return True

  
if __name__=="__main__":
  main(sys.argv)

