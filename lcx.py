import asyncio
import sys,getopt
import random
import struct

#协议编码格式
fmt_chap_salt='BBs'
fmt_chap_hash='BBsBs'
fmt_chap_result='BB'
fmt_bind_request='BHH'
fmt_bind_respone='BHBH'
fmt_connect_request='BHH'
fmt_connect_respone='BHBH'
fmt_data='BHHs'
fmt_dsconnect='BH'

class listen_args:
    tunnel_port=0
    users=list()

class slave_args:
    tunnel_port=0
    tunnel_add=''
    usr_name=''
    usr_pw=''
    remote_port=0
    local_port=0
    local_add=''

l_args=listen_args()
s_args=slave_args()

def hashSalt(password,salt):
    return hash(password+salt)

#随机生成6为salt
def getSalt():
    salt=''
    charSet='AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    charLen=len(charSet)-1
    for i in range(random.randint(6,12)):
        salt+=charSet[random.randint(0,charLen)]
    return salt

#验证密码是否正确
def validate(hashstr,password,salt):
    return hasattr==hash(password+salt)

#remote listen
def listen(opts,args):
    for opt,arg in opts:
        if opt == '-p':
            l_args.tunnel_port=int(arg)
        elif opt == '-u':
            l_args.users=arg.split(',')

    loop=asyncio.get_event_loop()
    coro=asyncio.start_server(handle_slave,'127.0.0.1',l_args.tunnel_port,loop=loop)
    server=loop.run_until_complete(coro)


async def handle_slave(reader,writer):
    salt=getSalt()
    msg=struct.pack('H'+fmt_chap_salt,2,0,len(salt),salt)
    writer.write(msg)


#与remote listen建立隧道连接
async def build_tunnel(port,user,remoteAdd,reader,writer,loop):
    ip,remotePort=remoteAdd.split(':')
    name,password=user.split(':')

    reader, writer=await asyncio.open_connection(ip,int(remotePort),loop=loop)
    salt=await reader.read(10)

    hashResult = hash(password+salt.decode())
    answer=name+'|'+hashResult
    await writer.write(answer.encode())

    succeed = await reader.read(10)
    if succeed.decode()=='1':
        await writer.write(port.encode())
        return port
    else:
        print("用户名或密码错误")
        exit(2)

def slave(opts,args):
    #获取参数
    for opt,arg in opts:
        if opt == '-p':
            port=arg
        elif opt == '-u':
            user=arg
        elif opt == '-r':
            remoteAdd=arg
        elif opt == '-l':
            serverAdd=arg
    
    loop=asyncio.get_event_loop()
    


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
