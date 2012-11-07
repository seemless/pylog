import os,sys, argparse
import pymongo

headers = ["id" , "Dir",	"Scenario",	"Kill Chain",	"Description",
           "Source",	"Destination",	"Status",	"Start Time (EDT)",
           "End Time (EDT)",	"Start Epoch",	"End Epoch", 'attack_duration']

types = ["flow","tcpdump","access_log"]

def ingestAttacks(path):
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

def buildQuery(typey, start={},end={},sips=[],dip=None):
  ret = {"type":typey}
  #create an empty dict for times
  ret['epoch']= {}
  if sips:
    ret["$or"] = sips
  if start:
    ret["epoch"].update(start)
  if end:
    ret["epoch"].update(end)
  if dip:
    ret["dip"] = dip

  #mongo will not accept an empty argument
  keys = ret.keys()
  for key in keys:
    if len(ret[key]) == 0:
      del ret[key]

  print("INFO: query built: %s" % (str(ret)))
  return ret

def getImportantVectors(attack):
  s = int(attack["Start Epoch"])
  e = int(attack['End Epoch'])
  print("timeframe %d" %(e-s))
  start = {"$gte":s}
  end = {"$lte":e}
  dip = attack['Destination']
  ops = [("sip","Source")]
  ips = []
  for db, att in ops:
    for i in attack[att].split("/"):
      ips.append({db:i})

  return (start,end,ips,dip)

def buildDataSet(connection, attack, typey="tcpdump"):

  ids = ["lr", attack['Dir'], attack['id'], typey,'timeframe']
  start,end,ips,dip = getImportantVectors(attack)

  if connection is not None:
    newCollection = connection['dapper_modular']["_".join(ids)]

  #get all from attack folder of designated type and time
  print("INFO: Using attack: %s" % str(attack))
  attackCol = connection["dapper_modular"]["attack_"+attack["Dir"]+"_events"]
  attCursor = attackCol.find(buildQuery(typey,start=start,end=end),limit=1)

  #put all attack data into new collection


  return True

def getAttackCounts(connection, attack,typey="tcpdump"):

  collName = "attack_"+attack['Dir']+"_events"
  col = connection["dapper_modular"][collName]
  start,end,ips,dip =getImportantVectors(attack)

  allOfType = col.find(buildQuery(typey)).count()
  attackTimeFrameCount = col.find(buildQuery(typey,start=start,end=end)).count()
  attackCount = col.find(buildQuery(typey,start=start,end=end,sips=ips,dip=dip)).count()
  return [("All",allOfType),("In time frame",attackTimeFrameCount),("Malicious activity",attackCount)]

def main(args):
  print(args)
  path = args[0]
  attackNum = args[1]
  #typey = args[2]

  try:
    connection = pymongo.Connection('localhost', 27017)
  except Exception as e:
    print("ERROR: Connection to database failed")
    return None

  attacks = ingestAttacks(path)
  attack = attacks[attackNum]
  counts = getAttackCounts(connection, attack)
  print("INFO: counts for attack %s: %s" % (attackNum,str(counts)) )
  #counts = buildDataSet(connection, attack)
  #print("INFO: number of events put into database: %s" % (str(counts)) )

  connection.close()

if __name__=="__main__":

  f_choices = ["5s6","5s19"]
  t_choices = ['tcpdump','access_log','flow']

  parser = argparse.ArgumentParser(description="Create Datasets and get metadata counts for DAPPER.")

  parser.add_argument('-f',"--attackFolder",help="The folder you want to build from.",
                      choices=f_choices, )
  parser.add_argument("-t","--type",help="The type of data you want to build.",
                                       choices=t_choices)
  parser.add_argument('-a','--attacks',help="A path to a CSV that contains attack data.")
  parser.add_argument('-n', '--attackNumber' , help='The ID number of the attack you are tagging', type=int)
  args = parser.parse_args()
  print args
  #main(args)