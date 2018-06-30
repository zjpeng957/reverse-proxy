import asyncio
import sys, getopt
import random
import struct
import hashlib
from enum import Enum

# 枚举每一种消息类型
com_type = Enum('com_type',
                ('chap_salt', 'chap_hash', 'chap_result', 'bind_request', 'bind_response', 'connect_request',
                 'connect_response', 'data', 'disconnect'))

requestID_count = 0  # 绑定端口请求时使用的requestID,每次请求使用并更新requestID_count
connectID_count = 0  # 建立连接时使用的connectID,每次请求使用并更新connectID_count
#id_to_port = []
#port_to_id = dict()
#req_to_port = []
#connected = dict()
#requesting = dict()


requestID_lock = asyncio.Lock()  # 给requestID_count加锁，保证requestID唯一
connectID_lock = asyncio.Lock()  # 给connectID_count加锁，保证connectID唯一
listen_writer = asyncio.StreamWriter  # 保存slave的writer
server_writer = {}  # 保存与server连接的writer
syn_que = []  # 用于slave与handle_server同步


# 保存从命令行获得的参数
class slave_args:
    tunnel_port = 0  # listen向内监听端口
    tunnel_add = ''  # listen向内监听ip
    usr_name = ''  # 用户名
    usr_pw = ''  # 密码
    bind_port = 0  # 要listen绑定的端口
    local_host_port = 0  # server的ip
    local_host_addr=''  # server的端口


s_args = slave_args()

loop = asyncio.get_event_loop()


# 根据密码和salt生成md5值
def hashSalt(password, salt):
    v = hashlib.md5(bytes(password + salt, encoding='utf-8')).hexdigest()
    return v


# local slave
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

    # 启动协程handle_listen处理与listen的连接
    loop = asyncio.get_event_loop()
    loop.run_until_complete(handle_listen())
    print("connecting to %d" % s_args.tunnel_port)


async def handle_listen():
    reader, writer = await asyncio.open_connection(s_args.tunnel_add, s_args.tunnel_port, loop=loop)

    global listen_writer,connectID_count,requestID_count
    listen_writer = writer

    # 开始chap认证
    # 接收listen发来正确的类型的消息获取salt值
    while True:
        length, = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        while command[0] != com_type.chap_salt.value:
            await reader.readexactly(length-3)
            length, = struct.unpack('H', await reader.readexactly(2))
            command = struct.unpack('B', await reader.readexactly(1))

        salt_len, = struct.unpack('B', await reader.readexactly(1))
        data = await reader.readexactly(salt_len)
        salt = bytes.decode(data)
        # 根据salt生成密码的md5值,将用户名和md5值发回给listen
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
            # 消息类型错误，重试
            reader.readexactly(length-3)
            continue
        result, = struct.unpack('B', await reader.readexactly(1))
        if result == 0:
            # 验证失败，重试
            continue
        print("chap succeed")
        break

    # 隧道建立完成,开始绑定端口
    while True:
        # 发送绑定请求和要绑定的端口
        msg = struct.pack('=HBHH', 7, com_type.bind_request.value, requestID_count, s_args.bind_port)
        requestID_count = requestID_count + 1
        writer.write(msg)
        # 接收绑定端口回复
        length, = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        if command[0] == com_type.bind_response.value:
            requestID,result,p = struct.unpack('=HBH', await reader.readexactly(5))
            if result == 1:
                print("bind %d succeed\n" % s_args.bind_port)
                break
            else:
                # 绑定失败，重试
                print("bind %d fail\n" % s_args.bind_port)
                continue
        else:
            # 消息类型错误，重试
            print("bind %d fail"%s_args.bind_port)
            reader.readexactly(length-3)

    # 端口绑定完成，开始处理连接请求和数据转发
    # slave处理server<-client的数据,handle_server处理server->到client的数据
    while True:
        length = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B', await reader.readexactly(1))
        if command[0] == com_type.connect_request.value:
            # 建立与local server的连接
            requestID, = struct.unpack('H', await reader.readexactly(2))
            listen_port, = struct.unpack('H', await reader.readexactly(2))
            # 选择唯一的connectID
            await connectID_lock
            try:
                # 建立与local server的连接
                client = asyncio.wait_for(
                    asyncio.ensure_future(
                        handle_server(requestID, connectID_count, s_args.local_host_addr, s_args.local_host_port)),
                    None)
                connectID_count += 1
            finally:
                connectID_lock.release()

        elif command[0] == com_type.data.value:
            # 将数据转发给server
            connectID, = struct.unpack('H', await reader.readexactly(2))
            data_len, = struct.unpack('H', await reader.readexactly(2))
            data = await reader.readexactly(data_len)
            server_writer[connectID].write(data)

        elif command[0] == com_type.disconnect.value:
            connectID, = struct.unpack('H', await reader.readexactly(2))
            print("%d disconnect"%connectID)
            server_writer[connectID].close()
            '''
            if syn_que[connectID].empty():
                await syn_que[connectID].put(connectID)  # 若syn_que为空，则表明server仍有数据，由handle_server处理连接的断开
            else:
                # server也无数据,直接断开连接
                syn_que[connectID].get_nowait()
                server_writer[connectID].close()
            '''

# 处理与local server的通信
# rid:requestID,id:connectID,addr:local server ip,request_port:local server端口
async def handle_server(rid,id, addr,request_port,):
    # 开启与server的连接,发回是否成功的消息
    try:
        reader, writer = await asyncio.open_connection(addr, int(request_port), loop=loop)
        msg = struct.pack('=HBHBH', 8, com_type.connect_response.value, rid, 1, id)
        listen_writer.write(msg)
    except asyncio.TimeoutError:
        msg = struct.pack('=HBHBH', 8, com_type.connect_response.value, rid, 0, id)
        listen_writer.write(msg)
    global server_writer
    server_writer[id] = writer
    #connected[request_port] = True

    try:
        while True:
            # 从client读取数据，设置超时时间
            data = await asyncio.wait_for(reader.read(100), timeout=5, loop=loop)
            print("reading %d..."%rid)
            if len(data) == 0:
                msg = struct.pack("=HBH", 5, com_type.disconnect.value, id)
                listen_writer.write(msg)
                break
            # 将数据转发给slave
            msg=struct.pack("=HBHH"+str(len(data))+"s",7+len(data),com_type.data.value,id,len(data),data)
            listen_writer.write(msg)
    except asyncio.TimeoutError:
        print("%d timeout"%id)
        #print(e)
        '''
        if syn_que[id].empty():
            # 若syn_que为空,表明client未关闭连接,发送断开连接请求
            await syn_que[id].put(id)
            msg=struct.pack("=HBH",5,com_type.disconnect.value,id)
            listen_writer.write(msg)
            await syn_que[id].join()
        else:
            # server已关闭连接，直接关闭
            syn_que[id].get_nowait()
            writer.close()
            print('closed')
        '''

if __name__ == "__main__":
    for i in range(0,1000):
        syn_que.append(asyncio.Queue())  # 用于listen和client通信
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:u:r:l:", [])  # 获取命令行参数
    except getopt.GetoptError:
        print("-r <remote address> -u <u1:p1> -p <bind port> -l <local server address>")
        sys.exit(2)

    slave(opts, args)  # 启动slave
