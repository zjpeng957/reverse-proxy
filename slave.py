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
id_to_port = []
port_to_id = dict()
req_to_port = []
connected = dict()
requesting = dict()


requestID_lock=asyncio.Lock()
connectID_lock=asyncio.Lock()
listen_writer=asyncio.StreamWriter
server_writer={}
syn_que=[]


class slave_args:
    tunnel_port = 0
    tunnel_add = ''
    usr_name = ''
    usr_pw = ''
    bind_port = 0
    local_host_port = 0
    local_host_addr=''
    port_pair = dict()


s_args = slave_args()

loop = asyncio.get_event_loop()


def hashSalt(password, salt):
    v = hashlib.md5(bytes(password + salt, encoding='utf-8')).hexdigest()
    return v


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

    global listen_writer,connectID_count,requestID_count
    listen_writer=writer

    # 开始chap认证
    while True:
        length, = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        while command[0] != com_type.chap_salt.value:
            length, = struct.unpack('H', await reader.readexactly(2))
            command = struct.unpack('B', await reader.readexactly(1))

        salt_len, = struct.unpack('B', await reader.readexactly(1))
        data = await reader.readexactly(salt_len)
        salt = bytes.decode(data)

        hash_val = hashSalt(s_args.usr_pw, salt)
        len_name = len(s_args.usr_name)
        len_hash = len(hash_val)
        msg = struct.pack('=HBB' + str(len_name) + 'sB' + str(len_hash) + 's', 5 + len_name + len_hash,
                          com_type.chap_hash.value, len_name, bytes(s_args.usr_name, encoding='utf-8'), len_hash,
                          bytes(hash_val, encoding='utf-8'))
        writer.write(msg)

        length, = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        if command[0] != com_type.chap_result.value:
            reader.readexactly(length-3)
            continue
        result, = struct.unpack('B', await reader.readexactly(1))
        if result == 0:
            continue
        print("chap succeed")
        break

    # 隧道建立完成,绑定端口
    while True:
        msg = struct.pack('=HBHH', 7, com_type.bind_request.value, requestID_count, s_args.bind_port)

        await requestID_lock
        try:
            requestID_count = requestID_count + 1
        finally:
            requestID_lock.release()
        writer.write(msg)
        #接收绑定端口回复
        length, = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        if command[0] == com_type.bind_response.value:
            requestID,result,p = struct.unpack('=HBH', await reader.readexactly(5))
            if result == 1:
                print("bind %d succeed\n" % s_args.bind_port)
                break
            else:
                print("bind %d fail\n" % s_args.bind_port)
                continue
        else:
            print("bind %d fail"%s_args.bind_port)
            reader.readexactly(length-3)

    while True:
        length = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        if command[0] == com_type.connect_request.value:
            requestID, = struct.unpack('H', await reader.readexactly(2))
            listen_port, = struct.unpack('H', await reader.readexactly(2))
            client = asyncio.wait_for(
                    asyncio.ensure_future(handle_server(requestID,connectID_count, s_args.local_host_addr,s_args.local_host_port)), None)
            await connectID_lock
            try:
                connectID_count += 1
            finally:
                connectID_lock.release()

        elif command[0] == com_type.data.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            data_len, = struct.unpack('H', await reader.readexactly(2))
            data = await reader.readexactly(data_len)
            server_writer[connectID].write(data)

        elif command[0] == com_type.disconnect.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            print("%d disconnect"%connectID)
            if syn_que[connectID].empty():
                await syn_que[connectID].put(connectID)
            else:
                syn_que[connectID].get_nowait()
                server_writer[connectID].close()


async def handle_server(rid,id, addr,request_port,):
    try:
        reader, writer = await asyncio.open_connection(addr, int(request_port), loop=loop)
        msg = struct.pack('=HBHBH', 8, com_type.connect_response.value, rid, 1, id)
        listen_writer.write(msg)
    except asyncio.TimeoutError:
        msg = struct.pack('=HBHBH', 8, com_type.connect_response.value, rid, 0, id)
        listen_writer.write(msg)
    global server_writer
    server_writer[id]=writer
    connected[request_port] = True

    try:
        while True:
             data = await asyncio.wait_for(reader.read(100), timeout=5, loop=loop)
             print("reading %d..."%rid)
             msg=struct.pack("=HBHH"+str(len(data))+"s",7+len(data),com_type.data.value,id,len(data),data)
             listen_writer.write(msg)
    except asyncio.TimeoutError:
        print("%d timeout"%id)

        if syn_que[id].empty():
            await syn_que[id].put(id)
            msg=struct.pack("=HBH",5,com_type.disconnect.value,id)
            listen_writer.write(msg)
            await syn_que[id].join()
        else:
            syn_que[id].get_nowait()
            writer.close()


if __name__ == "__main__":
    for i in range(0,1000):
        syn_que.append(asyncio.Queue())
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:u:r:l:", [])
    except getopt.GetoptError:
        print("lcx.py -m <runtype>")
        sys.exit(2)

    slave(opts, args)
