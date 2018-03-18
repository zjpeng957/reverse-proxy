import asyncio
import sys,getopt


def listen(opts,args):
    for opt,arg in opts:
        if opt == '-p':
            port=arg
        elif opt == '-u':
            users=arg.split(',')

def slave(opts,args):
    for opt,arg in opts:
        if opt == '-p':
            port=arg
        elif opt == '-u':
            users=arg.split(',')
        elif opt == '-r':
            remoteAdd=arg
        elif opt == '-l':
            serverAdd=arg


if __name__ == "__main__":
    try:
        opts,args=getopt.getopt(sys.argv[1:],"m:p:u:r:l:",[])
    except getopt.GetoptError:
        print("lcx.py -m <runtype>")
        sys.exit(2)
    for opt,arg in opts:
        if opt == "-m":
            if arg == "listen":
                listen(opts,args)
            if arg == "slave":
                slave(opts,args)
            else:
                print("use \'-m <type>\' to specify the type to execute.")
                exit(2)
