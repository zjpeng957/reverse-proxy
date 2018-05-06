import asyncio
import sys,getopt
import random
import struct
from enum import Enum

com_type=Enum('com_type',('chap_salt','chap_hash','chap_result','bind_request','bind_response','connect_request',
'connect_response','data','disconnect'))

requestID_count=0
connectID_count=0
recv_buffs=dict()
send_buffs=dict()
id_to_port=[]
port_to_id=dict()
req_to_port=[]
recv_locks=dict()
send_locks=dict()
connected=dict()
requesting=dict()

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
    remote_ports=[]
    local_host_ports=[]
    port_pair=dict()

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
    msg=struct.pack(fmt_chap_salt,4+len(salt),com_type.chap_salt,len(salt),salt)
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
    while (await chap(reader,writer))==False:
        pass
    print("chap succeed")
    requestID_count=0
    while True:
        for port,v in connected:
            if v==True:
                await recv_locks[port]
                try:
                    if len(recv_buffs[port])!=0:
                        msg=struct.pack(fmt_data,7+len(recv_buffs[port]),com_type.data,port_to_id[port],len(recv_buffs[port]),recv_buffs[port])
                        writer.write(msg)
                        writer.drain()
                finally:
                    recv_locks[port].release()
        for port,v in requesting:            
            if v==True:
                msg=struct.pack(fmt_connect_request,7,com_type.connect_request,requestID_count,port)
                requestID_count=requestID_count+1
                writer.write(msg)
                await writer.drain()

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
                recv_locks[bind_port]=asyncio.locks()
                send_locks[bind_port]=asyncio.locks()
        elif command==com_type.connect_response:
            requestID=struct.unpack('H',await reader.readexactly(2))
            result=struct.unpack('B',await reader.readexactly(1))
            if result==1:
                connectID=struct.unpack('H',await reader.readexactly(2))
                port=req_to_port[requestID]
                connected[port]=True
                port_to_id[port]=connectID
            else:
                await reader.readexactly(2)
        elif command==com_type.data:
            connectID=struct.unpack('H',await reader.readexactly(2))
            data_len=struct.unpack('H',await reader.readexactly(2))
            data=struct.unpack('H',await reader.readexactly(data_len))
            port=id_to_port[connectID]
            await send_locks[port]
            try:
                send_buffs[port].append(data)
            finally:
                send_locks[port].release()
        elif command==com_type.disconnect:
            server.close()
            loop.run_until_complete(server.wait_closed())
            return

async def handle_client(reader,writer):
    peer_host, peer_port, = writer.get_extra_info('peername')
    sock_host, sock_port, = writer.get_extra_info('sockname')
    
    requesting[sock_port]=True
    while(True):
        await send_locks[sock_port]
        try:
            if len(send_buffs[sock_port])!=0:
                writer.write(send_buffs[sock_port])
                await writer.drain()
                send_buffs[sock_port].clear()
        finally:
            send_locks[sock_port].release()

        await recv_locks[sock_port]
        try:
            recv_buffs[sock_port].append(await reader.read(100))
        finally:
            recv_locks[sock_port].release()
    

def slave(opts,args):
    #获取参数
    for opt,arg in opts:
        if opt == '-r':
            s_args.tunnel_add,s_args.tunnel_port=arg.split(':')
        elif opt == '-u':
            s_args.usr_name,s_args.usr_pw=arg.split(':')
        elif opt == '-p':
            s_args.remote_port=[int(p) for p in arg.split(',')]
        elif opt == '-l':
            s_args.local_host_ports=[p.split(':') for p in arg.split(',')]
    for i in range(len(s_args.remote_ports)):
        s_args.port_pair[s_args.remote_ports[i]]=int(s_args.local_host_ports[i][1])
    s_args.tunnel_port=int(s_args.tunnel_port)

    loop=asyncio.get_event_loop()
    loop.run_until_complete(handle_listen())
    print("connecting to %d"%s_args.tunnel_port)
    
async def handle_listen():
    reader,writer=await asyncio.open_connection(s_args.tunnel_add,s_args.tunnel_port,loop=loop)
    
    connectID_count=0

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
    print("chap succeed")
    #msg=struct.pack(fmt_bind_request,7,com_type.bind_request,1,)
    while True:
        for port,v in connected:            
            if v==True:
                msg=struct.pack(fmt_connect_request,8,com_type.connect_response,connectID_count,port)
                connectID_count=connectID_count+1
                writer.write(msg)
                await writer.drain()

        length=struct.unpack('H',await reader.readexactly(2))
        command=struct.unpack('B',await reader.readexactly(1))
        if command==com_type.bind_response:
            requestID=struct.unpack('H',await reader.readexactly(2))  
            result==struct.unpack('B',await reader.readexactly(1))
            
            await reader.readexactly(3)
        elif command==com_type.connect_request:
            requestID=struct.unpack('H',await reader.readexactly(2))
            listen_port=struct.unpack('H',await reader.readexactly(2))
            
            client=asyncio.wait_for(asyncio.ensure_future(handle_server(connectID_count,s_args.port_pair[listen_port])),None)
        elif command==com_type.data:
            connectID=struct.unpack('H',await reader.readexactly(2))
            data_len=struct.unpack('H',await reader.readexactly(2))
            data=struct.unpack('H',await reader.readexactly(data_len))
            await send_locks[connectID]
            try:
                send_buffs[connectID].append(data)
            finally:
                send_locks[connectID].release()
        elif command==com_type.disconnect:
            return
            
                  
    
async def handle_server(id,request_port):
    reader,writer=await asyncio.open_connection(s_args.local_host_ports[0][0],request_port,loop=loop)

    connected[request_port]=True

    while(True):
        await send_locks[request_port]
        try:
            if len(send_buffs[request_port])!=0:
                writer.write(send_buffs[request_port])
                await writer.drain()
                send_buffs[request_port].clear()
        finally:
            send_locks[request_port].release()

        await recv_locks[request_port]
        try:
            recv_buffs[request_port].append(await reader.read(100))
        finally:
            recv_locks[request_port].release()
        


#if __name__ == "__main__":
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
