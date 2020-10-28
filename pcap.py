from scapy.all import *
import os

def main():
    # print("hello")
    
    # print os.sys.path
    
    # scapy_cap = rdpcap('file.pcap')
    # for packet in scapy_cap:
    #     print packet[IPv6].src
    
    aPacket = IP(ttl=10)
    print(aPacket)
    print(aPacket.src)
    print(aPacket.dst)
    
    hexdump(aPacket)
    b = raw(aPacket)
    print(b)
    c = Ether(b)
    print(c)

if __name__ == "__main__":
    main()