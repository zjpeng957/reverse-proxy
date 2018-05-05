import asyncio
import sys,getopt
import random
import struct
from enum import Enum

com_type=Enum('com_type',('chap_salt','chap_hash','chap_result','bind_request','bind_response','connect_request',
'connect_response','data','disconnect'))

#协议编码格式
fmt_chap_salt='HBBs'
fmt_chap_hash='HBBsBs'
fmt_chap_result='HBB'
fmt_bind_request='HBHH'
fmt_bind_respone='HBHBH'
fmt_connect_request='HBHH'
fmt_connect_respone='HBHBH'
fmt_data='HBHHs'
fmt_dsconnect='HBH'
prefix='HB'

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

loop=asyncio.get_event_loop()

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

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

def find_pwd(name):
    for user in l_args.users:
        usr_name,usr_pw=user.split(':')
        if usr_name==name:
            return usr_pw
    
    return None


async def chap(reader,writer):
    salt=getSalt()
    msg=struct.pack(prefix+fmt_chap_salt,2,com_type.chap_salt,len(salt),salt)
    writer.write(msg)
    await writer.drain()
    length=struct.unpack('H',await reader.readexactly(2))
    command=struct.unpack('B',await reader.readexactly(1))
    count=0
    while command != com_type.chap_hash and count!=5:
        await reader.readexactly(length-3)
        length=struct.unpack('H',await reader.readexactly(2))
        command=struct.unpack('B',await reader.readexactly(1))
        count=count+1
    
    if count==5:
        return False

    name_len=struct.unpack('B',await reader.readexactly(1))
    name=struct.unpack('s',await reader.readexactly(name_len))
    hash_len=struct.unpack('B',await reader.readexactly(1))
    hash_val=struct.unpack('s',await reader.readexactly(name_len))
    
    usr_pw=find_pwd(name)
    if usr_pw!=None and validate(hash_val,usr_pw,salt)==True:
        msg=struct.pack(fmt_chap_result,4,com_type.chap_result,1)
        writer.write(msg)
        return True
    else:
        msg=struct.pack(fmt_chap_result,4,com_type.chap_result,1)
        writer.write(msg)
        return False

async def handle_slave(reader,writer):
    while chap(reader,writer)==False:
        pass

    while True:
        length=struct.unpack('H',await reader.readexactly(2))
        command=struct.unpack('B',await reader.readexactly(1))
        if command==com_type.bind_request:
            requestId,bind_port=struct.unpack('HH',await reader.readexactly(4))
            if bind_port==0:
                bind_port=random.randint(0,1000)
                try:
                    coro=asyncio.start_server(handle_client,'127.0.0.1',bind_port,loop=loop)
                    server=asyncio.wait_for(asyncio.ensure_future(coro),None)
                    msg=struct.pack(fmt_bind_respone,8,com_type.bind_response,requestId,1,bind_port)
                except asyncio.TimeoutError:
                    msg=struct.pack(fmt_bind_respone,8,com_type.bind_response,requestId,0,bind_port)
                writer.write(msg)
        elif command==com_type.connect_response:
            pass
        elif command==com_type.data:
            pass
        elif command==com_type.disconnect:
            pass
async def handle_client():
    pass 
    



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
        if opt == '-r':
            s_args.tunnel_add,s_args.tunnel_port=arg.split(':')
        elif opt == '-u':
            s_args.usr_name,s_args.usr_pw=arg.split(':')
        elif opt == '-p':
            s_args.remote_port=int(arg)
        elif opt == '-l':
            s_args.local_add,s_args.local_port=arg.split(':')
    s_args.local_port=int(s_args.local_port)
    s_args.tunnel_port=int(s_args.tunnel_port)

    loop=asyncio.get_event_loop()
    loop.run_until_complete(handle_listen())
    
async def handle_listen():
    reader,writer=await asyncio.open_connection(s_args.tunnel_add,s_args.tunnel_port,loop=loop)

    length=struct.unpack('H',await reader.readexactly(2))
    command=struct.unpack('B',await reader.readexactly(1))
    if command!=com_type.chap_salt:
        sys.exit(2)
    salt_len=struct.unpack('B',await reader.readexactly(1))
    salt=struct.unpack('s',await reader.readexactly(salt_len))
    
    hash_val=hashSalt(s_args.usr_pw,salt)
    msg=struct.pack(fmt_chap_hash,5+len(s_args.usr_name)+len(hash_val),com_type.chap_hash,len(s_args.usr_name),s_args.usr_name,len(hash_val),hash_val)
    writer.write(msg)

    length=struct.unpack('H',await reader.readexactly(2))
    command=struct.unpack('B',await reader.readexactly(1))
    if command!=com_type.chap_result:
        sys.exit(2)
    result=struct.unpack('B',await reader.readexactly(1))
    if(result==0):
        sys.exit(2)

    while True:
        length=struct.unpack('H',await reader.readexactly(2))
        command=struct.unpack('B',await reader.readexactly(1)) 
    

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
