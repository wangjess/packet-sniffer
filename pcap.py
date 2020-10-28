from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
import argparse
# import os

def main():
    init() # initialize colorama
    # print("hello")
    
    # define colors
    GREEN = Fore.GREEN
    RED = Fore.RED
    RESET = Fore.RESET
    
    # print os.sys.path
    
    # scapy_cap = rdpcap('file.pcap')
    # for packet in scapy_cap:
    #     print packet[IPv6].src
    
    # aPacket = IP(ttl=10)
    # print(aPacket)
    # print(aPacket.src)
    # print(aPacket.dst)
    
    # hexdump(aPacket)
    # b = raw(aPacket)
    # print(b)
    # c = Ether(b)
    # print(c)
    
    # packetsList = rdpcap('wifi.pcap')
    # print(packetsList)
    # print(packetsList[0])
    
    # for pkt in PcapReader('wifi.pcap'):
    #     ethSrc = pkt[Ether].src
    #     ethType = pkt[Ether].type
    #     print(ethSrc)
    #     print(ethType)
    
    parser = argparse.ArgumentParser(description = "HTTP Packet Sniffer" 
                                     + "Run arg spoofer before this so you don't capture your personal info")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    print("inside dmain")
    sniffPackets(iface)

def sniffPackets(iface = "wlan0"):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    print("insided SNIFFPAACKTES")
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        print("if")
        sniff(filter="port 80", prn=processPacket, iface=iface, store=False)
    else:
        print("else")
        # sniff with default interface
        sniff(filter="port 80", prn=processPacket, store=False)
        print("done with sniff")
        
    print("LEFT SNIFFPAACKTES")
        
def processPacket(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        print("insided PROCESSPACKETS")
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(format(GREEN) + format(ip) + " Requested " + format(url) + " with " + format(method))
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print("show data")
            # print(format(RED) + " Some useful Raw data: " + {packet[Raw].load}{RESET}")
    # print("LEFT PROCESSPACKETS")

if __name__ == "__main__":
    main()