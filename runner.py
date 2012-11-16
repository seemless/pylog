__author__ = 'Matthew Smith'

import logreg
import time

def main():
  print("Starting runner.py")
  field_names = ['bytes_in_flight','tcp_len',
                 'tcp_hdr_len','nxtseq',
                 'wscale_multiplier','wscale_shift','pdu_size',
                 'segment','segment_count','seq',
                 'stream','ttl',
                 'ip_fragment_count','ip_hdr_len','dummy'
                 ]


  data_sizes = [1000]
  r = data_sizes[::-1]
  indices = field_names[9:]
  attack_folders = ['5s6']
  ids = ['2']
  counter = 0
  with open("LR_Log", 'w') as fi:

    for a in attack_folders:
      for _id in ids:
        for ds in r:
          for i in indices:
            print("Running",a,_id,ds,i)
            #if i < len(field_names)-1:

            start = time.time()
            
            fi.write("INPUT| %d | %s \n" %(ds,str(i)))
            fi.flush()
            args = {'count':ds, 'id':_id,'fields':[i],'folder':a}
            acc = None
            w = None
            try:
              acc,w = logreg.LR(args)
            except Exception as e:
              acc = "Error"
              w = "Error"
              fi.write(str(e) +'\n')
              fi.flush()

            end = time.time()
            dur = str(end - start)
            rets = [str(acc),str(ds),str(i),str(w),dur]
            fi.write("OUTPUT| " + "|".join(rets) + '\n')
            fi.flush()
def test():
  d = ['d',1]
  print("|".join(d))


if __name__=="__main__": main()


