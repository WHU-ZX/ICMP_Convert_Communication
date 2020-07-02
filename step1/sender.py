# encoding:utf-8
import time
import struct
import socket
import select
from math import *
import sys
from sm4 import SM4Key

dst_addr = "182.92.236.19"
# dst_addr = "192.168.1.5"
port = 80
batch_size = 15
key0 = SM4Key(b"abcdefghijklmnop")

def calculate_chesksum(data):
    n=len(data)
    m=n % 2
    sum=0
    for i in range(0, n - m, 2):
        sum += (data[i]) + ((data[i+1]) << 8)#传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    if m:
        sum += (data[-1])
    #将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16) #如果还有高于16位，将继续与低16位相加
    answer = ~sum & 0xffff
    #  主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def ping(type, code, checksum, ID, sequence, payload):
    #  把字节打包成二进制数据
    imcp_packet = struct.pack('>BBHHH16s',type,code,checksum,ID,sequence,payload)
    icmp_chesksum = calculate_chesksum(imcp_packet)  #获取校验和
    #  把校验和传入，再次打包
    imcp_packet = struct.pack('>BBHHH16s',type,code,icmp_chesksum,ID,sequence,payload)
    return imcp_packet


def raw_socket(imcp_packet):
    '''
       连接套接字,并将数据发送到套接字
    '''
    #实例化一个socket对象，ipv4，原套接字，分配协议端口
    rawsocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    # #记录当前请求时间
    # send_request_ping_time = time.time()
    #发送数据到网络
    rawsocket.sendto(imcp_packet,(dst_addr,port))
    # #返回数据
    # return send_request_ping_time,rawsocket,dst_addr

# def reply_ping(send_request_ping_time,rawsocket,data_Sequence,timeout = 2):
#     while True:
#         #开始时间
#         started_select = time.time()
#         #实例化select对象，可读rawsocket，可写为空，可执行为空，超时时间
#         what_ready = select.select([rawsocket], [], [], timeout)
#         #等待时间
#         wait_for_time = (time.time() - started_select)
#         #没有返回可读的内容，判断超时
#         if what_ready[0] == []:  # Timeout
#             return -1
#         #记录接收时间
#         time_received = time.time()
#         #设置接收的包的字节为1024
#         received_packet, addr = rawsocket.recvfrom(1024)
#
#         # payload
#         payload = received_packet[28:]
#         print(payload)
#
#         #获取接收包的icmp头
#         #print(icmpHeader)
#         icmpHeader = received_packet[20:28]
#         #反转编码
#         type, code, checksum, packet_id, sequence = struct.unpack(
#             ">BBHHH", icmpHeader
#         )
#
#         if type == 0 and sequence == data_Sequence:
#             return time_received - send_request_ping_time
#
#         #数据包的超时时间判断
#         timeout = timeout - wait_for_time
#         if timeout <= 0:
#             return -1

def send(fileName):
    f = open(fileName)
    fileContent = f.read()
    print("文件内容:", fileContent)
    f.close()

    fileLen = len(fileContent)
    print("文件长度:", fileLen)

    pingTime = ceil(fileLen/batch_size) # ping 的次数
    print("ping的次数:", pingTime)

    send, accept, lost = 0, 0, 0
    sumtime, shorttime, longtime, avgtime = 0, 1000, 0, 0
    #TODO icmp数据包的构建
    type = 8 # ICMP Echo Request
    code = 0 # must be zero
    checksum = 0 # "...with value 0 substituted for this field..."
    ID = 33198 #Identifier
    sequence = 1 #Sequence number
    for i in range(0, pingTime):
        start = i*batch_size
        end = min((i+1)*batch_size, fileLen)
        if i == pingTime - 1:
            sequence = -i
        payload_body = str.encode(fileContent[start:end])
        encode_payload = key0.encrypt(payload_body, padding=True)

        # print(payload_body)
        #请求ping数据包的二进制转换
        icmp_packet = ping(type, code, checksum, ID, sequence + i, encode_payload)
        #连接套接字,并将数据发送到套接字
        raw_socket(icmp_packet)
        print("加密数据--- ",payload_body," ---为：",encode_payload)
        print("发送数据：",encode_payload)

        # send_request_ping_time, rawsocket, addr = raw_socket(icmp_packet)
        # #数据包传输时间
        # times = reply_ping(send_request_ping_time, rawsocket, data_Sequence + i)
        # if times > 0:
        #     print("来自 {0} 的回复: 字节=16 时间={1}ms".format(addr,int(times*1000)))
        #
        #     accept+=1
        #     return_time=int(times * 1000)
        #     sumtime += return_time
        #     if return_time > longtime:
        #         longtime = return_time
        #     if return_time < shorttime:
        #         shorttime = return_time
        #     time.sleep(0.7)
        # else:
        #     lost += 1
        #     print("请求超时。")


if __name__ == "__main__":
    # if len(sys.argv) < 2:
    #     sys.exit('Usage: ping.py <host>')
    # ping(sys.argv[1])
    send("../files/importantFile.txt")
    # host='www.baidu.com'
    # ping(host)