# from scapy.all import *
# import sys

def main():
    # sys.stdout.write("Hello")
    # print("hello")
    
    scapy_cap = rdpcap('file.pcap')
    for packet in scapy_cap:
        print packet[IPv6].src

if __name__ == "__main__":
    main()