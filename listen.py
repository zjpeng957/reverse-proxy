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

requestID_count = 0  # 建立连接时使用的requestID,每次请求使用并更新requestID_count
#connectID_count = 0
#id_to_port = []
#port_to_id = dict()
#req_to_port = []
#recv_locks = dict()
#send_locks = dict()
#connected = {}
#requested = {}
#requestId = 0
requestid_lock = asyncio.Lock()  # 给requestID_count加锁，保证requestID唯一
#requested_lock = asyncio.Lock()
con_to_req = {}  # 记录connect的requestID与connectID的对应关系


slave_writer = asyncio.StreamWriter  # 保存listen的writer
client_writer = {}  # 保存每个与client连接的writer
syn_que = []  # 用于client与listen之间的同步


# 保存从命令行活获得的参数
class listen_args:
    tunnel_port = 0  # 向内监听的端口
    users = list()  # 用户密码列表


l_args = listen_args()
loop = asyncio.get_event_loop()


# 根据密码生成加密过的md5值
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

    coro = asyncio.start_server(handle_slave, '127.0.0.1', l_args.tunnel_port, loop=loop)  # 启动listen服务器
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    # 启动事件循环，遇到键盘输入时终止
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())  # 等待服务器完全关闭
    loop.close()


# 程序支持多用户，用这个函数从用户名找到对应的密码
def find_pwd(name):
    for user in l_args.users:
        usr_name, usr_pw = user.split(':')
        if usr_name == name:
            return usr_pw
    return None


# chap认证
async def chap(reader, writer):
    # 获取salt将其打包后发送给slave
    salt = getSalt()
    msg = struct.pack('=HBB' + str(len(salt)) + 's', 4 + len(salt), com_type.chap_salt.value, len(salt),
                      bytes(salt, encoding='utf-8'))
    writer.write(msg)
    await writer.drain()
    # 获取slave发回的信息
    length, = struct.unpack('H', await reader.readexactly(2))
    command = struct.unpack('B', await reader.readexactly(1))
    # 不是chap认证期望的类型,验证失败
    if command[0] != com_type.chap_hash.value:
        await reader.readexactly(length - 3)
        return False
    # 获取slave发回的用户名和md5值
    name_len = struct.unpack('B', await reader.readexactly(1))
    data = await reader.readexactly(name_len[0])
    name = bytes.decode(data)
    hash_len = struct.unpack('B', await reader.readexactly(1))
    data = await reader.readexactly(hash_len[0])
    hash_val = bytes.decode(data)
    # 验证用户密码是否正确
    usr_pw = find_pwd(name)
    if usr_pw is not None and validate(hash_val, usr_pw, salt):
        msg = struct.pack('=HBB', 4, com_type.chap_result.value, 1)
        writer.write(msg)
        return True
    else:
        msg = struct.pack('=HBB', 4, com_type.chap_result.value, 1)
        writer.write(msg)
        return False


async def handle_slave(reader, writer):
    global slave_writer, syn_que, con_to_req
    slave_writer = writer
    # chap认证，失败自动重试
    result = await chap(reader, writer)
    while not result:
        result = await chap(reader, writer)
    print("chap succeed")

    while True:
        # 接收要绑定的端口
        length, = struct.unpack('H', await reader.readexactly(2))
        command, = struct.unpack('B', await reader.readexactly(1))
        #await reader.readexactly(length - 3)
        if command != com_type.bind_request.value:
            await reader.readexactly(length - 3)
            continue
        # 获取请求id和要绑定的端口
        req_id, bind_port = struct.unpack('HH',await reader.readexactly(4))
        if bind_port == 0:
            bind_port = random.randint(1000, 10000)
        try:
            # 根据绑定端口启动服务器监听client
            coro = asyncio.start_server(handle_client, '127.0.0.1', bind_port, loop=loop)
            server = asyncio.wait_for(asyncio.ensure_future(coro), None)
            # 回复slave是否绑定成功
            msg = struct.pack('=HBHBH', 8, com_type.bind_response.value, req_id, 1, bind_port)
            print("bind %d succeed\n" % bind_port)
            writer.write(msg)
            break
        except asyncio.TimeoutError:
            msg = struct.pack('=HBHBH', 8, com_type.bind_response.value, req_id, 0, bind_port)
            print("bind %d fail\n" % bind_port)
            writer.write(msg)
    # 开始处理client连接和数据转发
    # listen处理server->client的数据,handle_client处理server<-client的数据
    while True:
        print("recieving")
        length = struct.unpack('H', await reader.readexactly(2))
        command = struct.unpack('B',await reader.readexactly(1))

        print("command %d"%command)
        if command[0] == com_type.connect_response.value:
            requestID, = struct.unpack('H', await reader.readexactly(2))
            result, = struct.unpack('B', await reader.readexactly(1))
            print("hello %d" % requestID)
            if result == 1:
                # 连接成功,根据connectID获得对应的requestID,用syn_que通知client开始接收数据
                connectID, = struct.unpack('H', await reader.readexactly(2))
                con_to_req[connectID]=requestID
                await syn_que[requestID].put(connectID)
                print("listen:%d connected"%connectID)
            else:
                await reader.readexactly(2)
                print("listen:%d connect fail" % connectID)
        elif command[0] == com_type.data.value:
            # 将slave发来的数据转发给client
            connectID, = struct.unpack('H', await reader.readexactly(2))
            data_len, = struct.unpack('H', await reader.readexactly(2))
            data = await reader.readexactly(data_len)
            print(connectID)
            print("writing to %d"%connectID)
            client_writer[connectID].write(data)
        elif command[0] == com_type.disconnect.value:
            # slave发来断开连接的请求
            connectID,=struct.unpack('H',await reader.readexactly(2))
            rid=con_to_req[connectID]
            client_writer[rid].close()
            '''
            if syn_que[rid].empty():
                await syn_que[rid].put(connectID)  # 若syn_que为空，则表明client仍有数据，由handle_client处理连接的断开
            else:
                # client也无数据,直接断开连接
                syn_que[rid].get_nowait()
                client_writer[rid].close()
            '''

# 处理与client的通信
async def handle_client(reader, writer):
    global requestid_lock,syn_que,client_writer,requestID_count,loop
    peer_host, peer_port, = writer.get_extra_info('peername')
    sock_host, sock_port, = writer.get_extra_info('sockname')
    print("%d"%peer_port)
    # 为本次连接选择requestID
    await requestid_lock
    try:
        my_request=requestID_count
        requestID_count=requestID_count+1
    finally:
        requestid_lock.release()
    # 向slave发送连接请求
    msg = struct.pack("=HBHH",7,com_type.connect_request.value,my_request,sock_port)
    slave_writer.write(msg)
    # 等待server和slave建立连接
    my_id = await syn_que[my_request].get()

    print("add %d-----------------" % my_request)
    client_writer[my_id] = writer
    # 开始从client获取数据
    try:
        while True:
            #print("reading %d..." % my_request)
            # 从client读取数据，设置超时时间
            data = await asyncio.wait_for(reader.read(100), timeout=5,loop=loop)
            # 数据长度为零，表示已没有数据
            if len(data) == 0:
                msg = struct.pack("=HBH", 5, com_type.disconnect.value, my_id)
                slave_writer.write(msg)
                break
            # 将数据转发给slave
            msg = struct.pack("=HBHH"+str(len(data))+"s",7+len(data),com_type.data.value,my_id,len(data),data)
            slave_writer.write(msg)

    except asyncio.TimeoutError as e:
        print(e)
    finally:
        print("done %d"%my_id)
    '''
    if syn_que[my_request].empty():
        # 若syn_que为空,表明server未关闭连接,发送断开连接请求
        await syn_que[my_request].put(my_id)
        msg=struct.pack("=HBH",5,com_type.disconnect.value,my_id)
        slave_writer.write(msg)
        await syn_que[my_request].join()
    else:
        # server已关闭连接，直接关闭
        syn_que[my_request].get_nowait()
        writer.close()
    print("shut %d"%my_id)
    '''

if __name__ == "__main__":
    for i in range(0,1000):
        syn_que.append(asyncio.Queue())  # 用于listen和client通信
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:u:r:l:", [])  # 获取命令行参数
    except getopt.GetoptError:
        print("-p <port> -u <u1:p1,u2:p2,...>")
        sys.exit(2)

    listen(opts, args)  # 启动listen
