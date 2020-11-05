import socket, sys
from struct import *

def main():    
    # default port for socket 
    port = 80
    
    # 1) create an INET, raw socket
    try: 
        socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        # socket1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print "Socket successfully created"
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    try: 
        host_ip = socket.gethostbyname('localhost') 
    except socket.gaierror: 
        # this means could not resolve the host 
        print "There was an error resolving the host"
        sys.exit() 

    # connecting to the server 
    socket1.connect((host_ip, port)) 
    
    print "The socket has successfully connected to localhost on port == %s" %(host_ip) 
    
    # receive a packet
    return

    while True:
        print("go")
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

if __name__ == "__main__":
    main()