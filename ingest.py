import os,time,argparse
import pylog
import netpyfense
import pymongo

def main(args):
  root = '/opt/www-01.pch.net/IARPA_data/data/Releases/release5labeled/'
  attack = None
  attackFolder = args.path

  print("INFO: attack folder: %s" % attackFolder)
  print("INFO: Args: " + str(args))

  if args.attacks_path is not None and args.attack_number is not None and args.type is not None:
    attacks = ingestAttacks(args.attacks_path)
    attack = attacks[args.attack_number]
    attack['type'] = args.type
  else:
    return 2

  file_paths = gen_paths(root+attackFolder)
  for p in file_paths:
    if p is not None and 'index' not in p:
      success =  ingest(p,attackFolder,attack)
      print(success)

def gen_paths(path):
  #index files are htmls that are used for quick fs browsing,
  #they offer no information for the data set.
  if os.path.isdir(path):
    for path, dirlist, filelist in os.walk(path):
      for filename in filelist:
        yield os.path.join(path,filename)
  else:
      yield path


def ingestAttacks(path):
  headers = ["id" , "Dir",	"Scenario",	"Kill Chain",	"Description",
             "Source",	"Destination",	"Status",	"Start Time (EDT)",
             "End Time (EDT)",	"Start Epoch",	"End Epoch", 'attack_duration']
  attacks = {}
  counter = 0
  if os.path.isfile(path):
    print("found file: %s" % path)
    with open(path) as f:
      for line in f:
        splits = line.split(",")
        if len(headers) != len(splits):
          print("Bad data, headers and line length dont match")
          print(len(headers),len(splits))
          return None
        else:
          attack = dict(zip(headers,splits))
          attacks[splits[0]] = attack
          counter += 1
  return attacks
    
def ingest(path,attackFolder,attack=None):
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
        collection = connection["dapper_modular"]["attack_"+attackFolder+"_events"]
      except Exception as e:
        print("ERROR: in ingest database connection")
        print(e)
        return False
    
      for event in gen:
        #Make the database insertion
        if event is not None:
          event['attack_folder'] = attackFolder
          event['is_malicious'] = isMalicious(event,attack)
          try:
            #print(event)
            ids.extend([collection.insert(event)])
            counter += 1
          except Exception as e:
            print("ERROR: in database insertion at file: %s" % path)
            print("ERROR: malformed event: %s" % str(event))
            print(e)
            return False          
  
  #Time keeping!
  time2 = time.time()
  delta = time2-time1
  print ("INFO: there were %d events in %s and the file took %d seconds to parse" % (counter, path, delta))      
  print("INFO: events ingested into database: %d" % len(ids))
  print("INFO: ingest processing time: %d " % delta) 
  print("INFO: ingest time range: %d - %d" %(time1,time2))
  return True

def test(args):

  event = {"type":"tcpdump","sip":"1.2.3.4"}
  attack = ingestAttacks(args.attacks_path)[args.num]
  attack['type'] = args.type
  event['mal'] = isMalicious(event,attack)
  print event

def isMalicious(event, attack=None):
  ret = False
  if attack is not None:
    ret =  event['type'] == attack['type'] and\
          event['sip'] == attack['Source'] and\
          event['dip'] == attack['Destination'] and\
          event['epoch'] >= float(attack['Start Epoch']) and\
          event['epoch'] <= float(attack['End Epoch'])
  return ret

def meta(args):
  collection = None
  try:
    connection = pymongo.Connection('localhost', 27017)
    collection = connection["dapper_modular"]['attacks']
  except Exception as e:
    print("ERROR: in ingest database connection")
    print(e)
    return False

  if collection is None:
    return 2

  attacks = ingestAttacks(args.path)
  for attack in attacks.values():
    formatted = formatAttack(attack)
    try:
      collection.insert(formatted)
    except Exception as e:

      print("ERROR: malformed attack: %s" % str(formatted))
      print(e)
      return 2

  return 0

def formatAttack(attack):
  #  headers = ["id" , "Dir",	"Scenario",	"Kill Chain",	"Description",
  #"Source",	"Destination",	"Status",	"Start Time (EDT)",
  #"End Time (EDT)",	"Start Epoch",	"End Epoch", 'attack_duration']
  ret = dict()
  print(attack)
  ret['id'] = attack['id']
  ret['attack_folder'] = attack['Dir']
  ret['scenario'] = attack["Scenario"]
  ret['kill_chain'] = attack['Kill Chain']
  ret['desc'] = attack['Description']
  ret['sips'] = attack['Source']
  ret['dip'] = attack['Destination']
  ret['status'] = attack['Status']
  ret['start_time'] = attack['Start Time (EDT)']
  ret['end_time'] = attack['End Time (EDT)']
  ret['start_epoch'] = float(attack['Start Epoch'])
  ret['end_epoch'] = float(attack['End Epoch'])
  ret['attack_duration'] = float(attack['attack_duration'])
  return ret


if __name__=="__main__":
  f_choices = ["5s6","5s19"]
  t_choices = ['tcpdump','access_log','flow']

  parser = argparse.ArgumentParser(description="Create Datasets, ingest, and get metadata counts for DAPPER.")
  subparsers = parser.add_subparsers()

  #add main parser + args
  parser_ingest = subparsers.add_parser("ingest")
  parser_ingest.add_argument('-f',"--attackFolder",help="The folder you want to ingest and build from.", dest='path',
    choices=f_choices, )
  parser_ingest.add_argument("-t","--type",help="The type of data you want to build.", dest='type',
    choices=t_choices)
  parser_ingest.add_argument('-a','--attacks',help="A path to a CSV that contains attack data.", dest='attacks_path')
  parser_ingest.add_argument('-n', '--attackNumber' , help='The ID number of the attack you are tagging',
                      dest='attack_number')
  parser_ingest.set_defaults(func=main)

  #add meta data parser
  parser_meta = subparsers.add_parser('meta')
  parser_meta.add_argument("path")
  parser_meta.set_defaults(func=meta)

  #add testing parser + args
  parser_test = subparsers.add_parser("test")
  parser_test.add_argument('attacks_path')
  parser_test.add_argument("num")
  parser_test.add_argument("type")
  parser_test.set_defaults(func=test)
  args = parser.parse_args()

  #make the magic happen
  args.func(args)
