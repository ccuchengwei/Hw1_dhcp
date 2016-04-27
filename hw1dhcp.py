import socket
import struct
import argparse
from uuid import getnode as get_mac
from random import randint
MAX_BYTES=65535
def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb
def changIPInByte(rawip):
    ip=rawip.split('.')
    byte=b''
    for i in range(4):
        byte+=struct.pack('!B',int(ip[i]))
    return byte
class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'                #Message type: Boot Request (1)
        packet += b'\x01'                #Hardware type: Ethernet
        packet += b'\x06'                #Hardware address length: 6
        packet += b'\x00'                #Hops: 0 
        packet += self.transactionID     #Transaction ID
        packet += b'\x00\x00'            #Seconds elapsed: 0
        packet += b'\x80\x00'            #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'    #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'    #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'    #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'    #Relay agent IP address: 0.0.0.0
        packet += macb
        packet += b'\x00' * 10           #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67           #Server host name not given
        packet += b'\x00' * 125          #Boot file name not given
        packet += b'\x63\x82\x53\x63'    #Magic cookie: DHCP
        packet += b'\x35\x01\x01'        #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'#Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'                #End Option
        return packet
    

class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack(data)
    
    def unpack(self,data):
        if self.data[4:8] == self.transID :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))

                
    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address']
        val = [self.DHCPServerIdentifier, self.offerIP]
        for i in range(2):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        

class Request:
	def __init__(self, data):
		self.data = data
		
		
	def buildpack(self):
		packet=b''
		packet=self.data[:16]
		packet+=b'\x00' * 4
		packet+=self.data[20:240]
		packet+=b'\x35\x01\x03'                            # Option53: length1 , type 3 DHCP Request 
		packet+=b'\x32\x04'+self.data[16:20]               # Option 50: length 4 , request IP
		packet+=b'\x36\x04'+self.data[245:249]             # Option 54: length 4 , identifier
		packet+=b'\xff'
		return packet
	
def server(sp,cp):
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
             # request identify
    try:
        dhcps.bind(('', sp))    #we want to send from port 68
    except Exception as e:
        print('port {} in use...'.format(sp))
        dhcps.close()
        input('press any key to quit...')
        exit()
    print('Listening at {}'.format(dhcps.getsockname()))
    print(socket.gethostbyname(socket.gethostname()))
    selfIP=changIPInByte(socket.gethostbyname(socket.gethostname()))
    dhcpserverIP=b'\x36\x04'+selfIP 
    while True:
        data , address = dhcps.recvfrom(MAX_BYTES)
        if data[240:].find(b'\x35\x01\x01')!=-1:
            ipoffer = b'\x0a'
            for i in range(3):
                t = randint(0, 255)
                ipoffer += struct.pack('!B', t)
            offerpack =b'\x02'+data[1:16]
            offerpack+=ipoffer
            offerpack+=data[20:240]
            offerpack+=b'\x35\x01\x02'
            offerpack+=b'\x36\x04'+selfIP 
            offerpack+=b'\xff'
            dhcps.sendto(offerpack,('<broadcast>',cp))
            print("Send Offer")
			
        if data[240:].find(b'\x35\x01\x03')!=-1:
            
            if data[240:].find(dhcpserverIP)!=-1:
                
                findip=data[240:].find(b'\x32\x04')
                requestIP=data[240:][findip+2:findip+6]
                ackpack=b'\x02'+data[1:16]
                ackpack+=requestIP
                ackpack+=data[20:240]
                ackpack+=b'\x35\x01\x05'
                ackpack+=b'\xff'
                dhcps.sendto(ackpack,('<broadcast>',cp))
                print("Send ACK")
            else:
                continue			

			
def clint(sp,cp):
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    try:
        dhcps.bind(('', cp))    
    except Exception as e:
        print('port {} in use...'.format(cp))
        dhcps.close()
        input('press any key to quit...')
        exit()
 
    #buiding and sending the DHCPDiscover packet
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.buildPacket(), ('<broadcast>', sp))
    
    print('DHCP Discover sent waiting for reply...\n')
	    #receiving DHCPOffer packet  
    dhcps.settimeout(3)
    try:
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            offer = DHCPOffer(data, discoverPacket.transactionID)
            if offer.offerIP:
                offer.printOffer()
                Requestpacket = Request(data);
                dhcps.sendto(Requestpacket.buildpack(), ('<broadcast>', sp))
                print("Send Request")
                data, address = dhcps.recvfrom(MAX_BYTES)
                break
    except socket.timeout as e:
        print(e)
    
    dhcps.close()   #we close the socket
    
    input('press any key to quit...')
    exit()
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='DHCP Connection')
    parser.add_argument('task', choices = ['clint','server'] , help='clint or server')
    parser.add_argument('-sp' , help='server port default 67',default='67')
    parser.add_argument('-cp' , help='clint port default 68',default='68')
    args=parser.parse_args()
    if args.task == 'clint' :
        clint(int(args.sp),int(args.cp))
    elif args.task == 'server' :
        server(int(args.sp),int(args.cp))
	