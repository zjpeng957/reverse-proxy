import asyncio
import sys, getopt
import random
import struct
import hashlib
from enum import Enum

com_type = Enum('com_type',
                ('chap_salt', 'chap_hash', 'chap_result', 'bind_request', 'bind_response', 'connect_request',
                 'connect_response', 'data', 'disconnect'))

requestID_count = 0
connectID_count = 0
recv_buffs = dict()
send_buffs = dict()
id_to_port = []
port_to_id = dict()
req_to_port = []
recv_locks = dict()
send_locks = dict()
connected={}
requested={}
requestId=0
requestid_lock=asyncio.Lock()
requested_lock=asyncio.Lock()
con_to_req={}
# 协议编码格式
fmt_chap_salt = 'HBB8s'
fmt_chap_hash = 'HBBsBs'
fmt_chap_result = 'HBB'
fmt_bind_request = 'HBHH'
fmt_bind_respone = 'HBHBH'
fmt_connect_request = 'HHHH'
fmt_connect_respone = 'HBHBH'
fmt_data = 'HHHHs'
fmt_dsconnect = 'HBH'
prefix = 'HB'

slave_writer=asyncio.StreamWriter
client_writer={}
syn_que=[]
syn_events=[]
class listen_args:
    tunnel_port = 0
    users = list()


class slave_args:
    tunnel_port = 0
    tunnel_add = ''
    usr_name = ''
    usr_pw = ''
    remote_ports = []
    local_host_ports = []
    port_pair = dict()


l_args = listen_args()
s_args = slave_args()

loop = asyncio.get_event_loop()


def hashSalt(password, salt):
    v = hashlib.md5(bytes(password + salt, encoding='utf-8')).hexdigest()
    return v


# 随机生成6为salt
def getSalt():
    salt = ''
    charSet = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    charLen = len(charSet) - 1
    for i in range(8):
        salt += charSet[random.randint(0, charLen)]
    return salt


# 验证密码是否正确
def validate(hashstr, password, salt):
    return hashstr == hashSalt(password, salt)


# remote listen
def listen(opts, args):
    for opt, arg in opts:
        if opt == '-p':
            l_args.tunnel_port = int(arg)
        elif opt == '-u':
            l_args.users = arg.split(',')

    loop = asyncio.get_event_loop()

    coro = asyncio.start_server(handle_slave, '127.0.0.1', l_args.tunnel_port, loop=loop)
    server = loop.run_until_complete(coro)

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
        usr_name, usr_pw = user.split(':')
        if usr_name == name:
            return usr_pw
    return None


#chap认证
async def chap(reader, writer):
    salt = getSalt()

    msg = struct.pack('=HBB' + str(len(salt)) + 's', 4 + len(salt), com_type.chap_salt.value, len(salt),
                      bytes(salt, encoding='utf-8'))
    writer.write(msg)
    await writer.drain()
    length = struct.unpack('H', await reader.readexactly(2))
    command = struct.unpack('B', await reader.readexactly(1))
    count = 0
    while command[0] != com_type.chap_hash.value and count != 5:
        await reader.readexactly(length - 3)
        length = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        count = count + 1

    if count == 5:
        return False

    name_len = struct.unpack('B', await reader.readexactly(1))
    data = await reader.readexactly(name_len[0])
    name = bytes.decode(data)
    hash_len = struct.unpack('B', await reader.readexactly(1))
    data = await reader.readexactly(hash_len[0])
    hash_val = bytes.decode(data)

    usr_pw = find_pwd(name)
    if usr_pw != None and validate(hash_val, usr_pw, salt) == True:
        msg = struct.pack(fmt_chap_result, 4, com_type.chap_result.value, 1)
        writer.write(msg)
        return True
    else:
        msg = struct.pack(fmt_chap_result, 4, com_type.chap_result.value, 1)
        writer.write(msg)
        return False


async def handle_slave(reader, writer):
    global slave_writer,requested,connected,requested_lock,syn_que,con_to_req
    slave_writer=writer
    result = await chap(reader, writer)
    while result == False:
        result = await chap(reader, writer)
    print("chap succeed")

    while True:
        #接收要绑定的端口
        length = struct.unpack('H', await reader.readexactly(2))
        command, t = struct.unpack('BB', await reader.readexactly(2))

        data = await reader.readexactly(4)
        req_id, bind_port = struct.unpack('HH',data)
        if bind_port == 0:
            bind_port = random.randint(1000, 10000)
        try:
            coro = asyncio.start_server(handle_client, '127.0.0.1', bind_port, loop=loop)
            server = asyncio.wait_for(asyncio.ensure_future(coro), None)
            msg = struct.pack('HHHHH', 10, com_type.bind_response.value, req_id, 1, bind_port)
            print("bind %d succeed\n" % bind_port)
            writer.write(msg)
            break
        except asyncio.TimeoutError:
            msg = struct.pack(fmt_bind_respone, 8, com_type.bind_response.value, req_id, 0, bind_port)
            print("bind %d fail\n" % bind_port)
            writer.write(msg)

    requestID_count = 0
    requestID_count = 0
    while True:
        print("recieving")
        data=await reader.readexactly(2)
        length = struct.unpack('H', data)
        data = await reader.readexactly(2)
        command = struct.unpack('H',data)

        print("command %d"%command)
        if command[0] == com_type.connect_response.value:
            requestID, = struct.unpack('H', await reader.readexactly(2))
            result, = struct.unpack('B', await reader.readexactly(1))
            print("hello %d" % requestID)
            if result == 1:
                connectID, = struct.unpack('H', await reader.readexactly(2))
                con_to_req[connectID]=requestID
                await requested_lock
                try:
                    connected[connectID] = True
                    requested[requestID]=connectID
                    await syn_que[requestID].put(connectID)
                finally:
                    requested_lock.release()

                print("listen:%d connected"%connectID)
            #    port_to_id[port] = connectID
            else:
                await reader.readexactly(2)
                print("listen:%d connect fail" % connectID)
        elif command[0] == com_type.data.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            data_len, = struct.unpack('H', await reader.readexactly(2))
            data = await reader.readexactly(data_len)
#            port = id_to_port[connectID]
            print(connectID)

            print("writing to %d"%connectID)

            client_writer[connectID].write(data)

        elif command[0] == com_type.disconnect.value:
            connectID,=struct.unpack('H',await reader.readexactly(2))
            rid=con_to_req[connectID]
            if syn_que[rid].empty():
                await syn_que[rid].put(connectID)
            else:
                syn_que[rid].get_nowait()
                client_writer[rid].close()


async def handle_client(reader, writer):
    global requestid_lock,requested,requested_lock,syn_que,client_writer,requestID_count,loop
    peer_host, peer_port, = writer.get_extra_info('peername')
    sock_host, sock_port, = writer.get_extra_info('sockname')
    print("%d"%peer_port)

    await requestid_lock
    try:
        my_request=requestID_count
        requestID_count=requestID_count+1
    finally:
        requestid_lock.release()

    await requested_lock
    try:
        requested[my_request]=-1
    finally:
        requested_lock.release()

    msg=struct.pack("=HHHH",8,com_type.connect_request.value,my_request,sock_port)
    slave_writer.write(msg)


    my_id = await syn_que[my_request].get()

    print("add %d-----------------" % my_request)

    client_writer[my_id] = writer

    connected[my_id] = True

    try:
        while True:
            print("reading %d..." % my_request)
            data = await asyncio.wait_for(reader.read(100), timeout=5,loop=loop)
            if len(data)==0:
                break
            msg=struct.pack("=HHHH"+str(len(data))+"s",7+len(data),com_type.data.value,my_id,len(data),data)
            slave_writer.write(msg)
            #data = await asyncio.wait_for(reader.read(100),5,loop=loop)
    except asyncio.TimeoutError as e:
        print(e)
    finally:
        print("done %d"%my_id)

    if syn_que[my_request].empty():
        await syn_que[my_request].put(my_id)
        msg=struct.pack("=HHH",5,com_type.disconnect.value,my_id)
        slave_writer.write(msg)
        await syn_que[my_request].join()
    else:
        syn_que[my_request].get_nowait()
        writer.close()
    print("shut %d"%my_id)

async def read_data(writer,reader,mid):
    data = await reader.read(100)
    msg = struct.pack("=HHHH" + str(len(data)) + "s", 7 + len(data), com_type.data.value, mid, len(data), data)
    writer.write(msg)

if __name__ == "__main__":
    for i in range(0,1000):
        syn_que.append(asyncio.Queue())
        syn_events.append(asyncio.Event())

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:u:r:l:", [])
    except getopt.GetoptError:
        print("lcx.py -m <runtype>")
        sys.exit(2)

    listen(opts, args)
