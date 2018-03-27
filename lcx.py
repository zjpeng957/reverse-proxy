import asyncio
import sys,getopt
import random

def hashSalt(password,salt):
    return hash(password+salt)

#随机生成6为salt
def getSalt():
    salt=''
    charSet='AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    charLen=len(charSet)-1
    for i in range(6):
        salt+=charSet[random.randint(0,charLen)]
    return salt

#验证密码是否正确
def validate(hashstr,password,salt):
    return hasattr==hash(password+salt)

def listen(opts,args):
    for opt,arg in opts:
        if opt == '-p':
            port=arg
        elif opt == '-u':
            users=arg.split(',')

    asyncio.get_event_loop()

#与remote listen建立隧道连接
async def build_tunnel(port,user,remoteAdd,loop):
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
