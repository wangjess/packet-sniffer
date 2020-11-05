# from scapy.all import *
# from scapy.layers.http import HTTPRequest
# from colorama import init, Fore
# import argparse
import socket, sys
from struct import *
# import os

def main():    
    # default port for socket 
    port = 80
    
    # 1) create an INET, raw socket
    try: 
        # socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        socket1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print "Socket successfully created"
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    try: 
        host_ip = socket.gethostbyname('www.google.com') 
    except socket.gaierror: 
        # this means could not resolve the host 
        print "There was an error resolving the host"
        sys.exit() 

    # connecting to the server 
    socket1.connect((host_ip, port)) 
    
    print "The socket has successfully connected to google on port == %s" %(host_ip) 
    
    # receive a packet
    while True:
        # print("go")
        # print socket1.recvfrom(80) # halts here
        # print("wtf")
        
        packet = socket1.recvfrom(1000)
        print("after recvfrom")
	
        #packet string from tuple
        packet = packet[0]
        
        #take first 20 characters for the ip header
        ip_header = packet[0:20]
        
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        
        tcp_header = packet[iph_length:iph_length+20]
        
        #now unpack them :)
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        
        print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
        
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
        
        #get data from the packet
        data = packet[h_size:]
        
        print 'Data : ' + data
        print
    
    # parser = argparse.ArgumentParser(description = "HTTP Packet Sniffer" 
    #                                  + "Run arg spoofer before this so you don't capture your personal info")
    # parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    # parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

#     # parse arguments
#     args = parser.parse_args()
#     iface = args.iface
#     show_raw = args.show_raw
#     print("inside dmain")
#     sniffPackets(iface)

# def sniffPackets(iface = "wlan0"):
#     """
#     Sniff 80 port packets with `iface`, if None (default), then the
#     Scapy's default interface is used
#     """
#     print("insided SNIFFPAACKTES")
#     if iface:
#         # port 80 for http (generally)
#         # `process_packet` is the callback
#         print("if")
#         sniff(filter="port 80", prn=processPacket, iface=iface, store=False)
#     else:
#         print("else")
#         # sniff with default interface
#         sniff(filter="port 80", prn=processPacket, store=False)
#         print("done with sniff")
        
#     print("LEFT SNIFFPAACKTES")
        
# def processPacket(packet):
#     """
#     This function is executed whenever a packet is sniffed
#     """
#     if packet.haslayer(HTTPRequest):
#         print("insided PROCESSPACKETS")
#         # if this packet is an HTTP Request
#         # get the requested URL
#         url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
#         # get the requester's IP Address
#         ip = packet[IP].src
#         # get the request method
#         method = packet[HTTPRequest].Method.decode()
#         print(format(GREEN) + format(ip) + " Requested " + format(url) + " with " + format(method))
#         if show_raw and packet.haslayer(Raw) and method == "POST":
#             # if show_raw flag is enabled, has raw data, and the requested method is "POST"
#             # then show raw
#             print("show data")
#             # print(format(RED) + " Some useful Raw data: " + {packet[Raw].load}{RESET}")
    # print("LEFT PROCESSPACKETS")

if __name__ == "__main__":
    main()