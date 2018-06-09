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
connected = dict()
requesting = dict()

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

listen_writer=asyncio.StreamWriter
server_writer={}


class listen_args:
    tunnel_port = 0
    users = list()


class slave_args:
    tunnel_port = 0
    tunnel_add = ''
    usr_name = ''
    usr_pw = ''
    bind_port = 0
    local_host_port = 0
    local_host_addr=''
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


def find_pwd(name):
    for user in l_args.users:
        usr_name, usr_pw = user.split(':')
        if usr_name == name:
            return usr_pw

    return None


async def chap(reader, writer):
    salt = getSalt()

    msg = struct.pack('HBB' + str(len(salt)) + 's', 4 + len(salt), com_type.chap_salt.value, len(salt),
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
    # name=struct.unpack('s',)
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


def slave(opts, args):
    # 获取参数
    for opt, arg in opts:
        if opt == '-r':
            s_args.tunnel_add, s_args.tunnel_port = arg.split(':')
        elif opt == '-u':
            s_args.usr_name, s_args.usr_pw = arg.split(':')
        elif opt == '-p':
            s_args.bind_port = int(arg)
        elif opt == '-l':
            s_args.local_host_addr,s_args.local_host_port = arg.split(':')
    s_args.tunnel_port = int(s_args.tunnel_port)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(handle_listen())
    print("connecting to %d" % s_args.tunnel_port)


async def handle_listen():
    reader, writer = await asyncio.open_connection(s_args.tunnel_add, s_args.tunnel_port, loop=loop)

    global listen_writer
    listen_writer=writer

    connectID_count = 0
    requestID_count = 0

    data = await reader.readexactly(2)
    length = struct.unpack('H', data)
    data = await reader.readexactly(1)
    command = struct.unpack('B', data)
    if command[0] != com_type.chap_salt.value:
        sys.exit(2)
    salt_len = struct.unpack('B', await reader.readexactly(1))
    data = await reader.readexactly(salt_len[0]);
    salt = bytes.decode(data)

    hash_val = hashSalt(s_args.usr_pw, salt)
    len_name = len(s_args.usr_name)
    len_hash = len(hash_val)
    msg = struct.pack('HBB' + str(len_name) + 'sB' + str(len_hash) + 's', 5 + len_name + len_hash,
                      com_type.chap_hash.value, len_name, bytes(s_args.usr_name, encoding='utf-8'), len_hash,
                      bytes(hash_val, encoding='utf-8'))
    writer.write(msg)

    length = struct.unpack('H', await reader.readexactly(2))
    command = struct.unpack('B', await reader.readexactly(1))
    if command[0] != com_type.chap_result.value:
        sys.exit(2)
    result = struct.unpack('B', await reader.readexactly(1))
    if (result[0] == 0):
        sys.exit(2)
    print("chap succeed")

    # 隧道建立完成,绑定端口
    msg = struct.pack('HBBHH', 8, com_type.bind_request.value, 0xff, 2, s_args.bind_port)
    requestID_count = requestID_count + 1;
    writer.write(msg)
    #接收绑定端口回复
    length = struct.unpack('H', await reader.readexactly(2))
    command = struct.unpack('H', await reader.readexactly(2))
    if command[0] == com_type.bind_response.value:
        data=await reader.readexactly(6)
        requestID,result,p = struct.unpack('HHH', data)
        #result == struct.unpack('B', await reader.readexactly(1))
        if result == 1:
            print("bind %d succeed\n" % s_args.bind_port)
        else:
            print("bind %d fail\n" % s_args.bind_port)
            exit(2)
    else:
        print("bind %d fail"%s_args.bind_port)
        exit(2)
    while True:
        length = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('H', await reader.readexactly(2))
        if command[0] == com_type.bind_response.value:
            requestID = struct.unpack('H', await reader.readexactly(2))
            result, = struct.unpack('B', await reader.readexactly(1))
            if result == 1:
                print("bind %d succeed\n" % requestID)
            else:
                print("bind %d succeed\n" % requestID)
            await reader.readexactly(3)
        elif command[0] == com_type.connect_request.value:
            requestID, = struct.unpack('H', await reader.readexactly(2))
            listen_port, = struct.unpack('H', await reader.readexactly(2))
            try:
                client = asyncio.wait_for(
                    asyncio.ensure_future(handle_server(connectID_count, s_args.local_host_addr,s_args.local_host_port)), None)
                msg = struct.pack('=HHHBH', 9, com_type.connect_response.value, requestID, 1, connectID_count)
                connectID_count+=1
            except asyncio.TimeoutError:
                msg = struct.pack('=HHHBH',9,com_type.connect_response.value,requestID,0,connectID_count)
            writer.write(msg)
        elif command[0] == com_type.data.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            data_len, = struct.unpack('H', await reader.readexactly(2))
            data = await reader.readexactly(data_len)
            #server_writer[connectID].write(data)
            #print(connectID)
            '''
            await send_locks[connectID]
            try:
                send_buffs[connectID].append(data)
            finally:
                send_locks[connectID].release()
            '''
        elif command[0] == com_type.disconnect.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            server_writer[connectID].close()



async def handle_server(id, addr,request_port):
    reader, writer = await asyncio.open_connection(addr, int(request_port), loop=loop)
    global server_writer
    server_writer[id]=writer
    connected[request_port] = True
    #print("comes %d"%id)
    #接收来自local server的数据并转发给remote listen

    data = await reader.read(100)
    while len(data)!=0:
        msg=struct.pack("=HHHH"+str(len(data))+"s",7+len(data),com_type.data.value,id,len(data),data)
        listen_writer.write(msg)
        data=await reader.read(100)

    #关闭连接
    #msg = struct.pack("=HHH", 5, com_type.disconnect.value, id)
    #listen_writer.write(msg)

    '''
    while (True):
        await send_locks[request_port]
        try:
            if len(send_buffs[request_port]) != 0:
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
    '''

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:u:r:l:", [])
    except getopt.GetoptError:
        print("lcx.py -m <runtype>")
        sys.exit(2)

    slave(opts, args)
