import os,sys
import hashlib

def main(args):
    print("INFO: args: ", args)

       
    if os.path.isdir(args[0]):
        with open(args[1], 'w') as filey: 
            for x,y,files in os.walk(args[0]):
                #print(x,y,files)
                for f in files:
                    digest = md5_file(x+"/"+f)
                    filey.write(digest +"\n")
                
        




def md5_file(path):
    md5 = hashlib.md5()
    with open(path,'rb') as f: 
        for chunk in iter(lambda: f.read(32768), b''): 
            md5.update(chunk)
    return md5.hexdigest()

if __name__=="__main__": main(sys.argv[1:])