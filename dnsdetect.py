#! /usr/bin/python

from scapy.all import *
import sys, getopt
import os
import os.path
import ConfigParser
import socket
import time

ifile = ''
data = {}
bpf=''

def querysniff(pkt):
	#print ifile
	val=''
	
	if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst

		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			#print "query: "+str(pkt[DNS].id)+"  " + str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			data[pkt[DNS].id]='0'
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:
                        #print "Reply: "+str(pkt[DNS].id)+"  " + str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")" + ": " + str(pkt[DNSRR].rdata)
			if pkt[DNS].id in data:
				if data[pkt[DNS].id]=='0':
					data[pkt[DNS].id]=str(pkt[DNSRR].rdata)
				elif data[pkt[DNS].id]==str(pkt[DNSRR].rdata):
					print 'retransmission happened'
				else:
					print time.strftime("%Y-%m-%d %H:%M") + '    DNS poisoning attempt'
					print 'TXID: '+str(pkt[DNS].id)+ '   Request: '+pkt.getlayer(DNS).qd.qname
					print 'Answer1: '+data[pkt[DNS].id]
					print 'Answer2: '+str(pkt[DNSRR].rdata)
					del data[pkt[DNS].id]
					print '****************************************************************'
		if len(data)==1000:
			data.clear()
		


def main(argv):
   interface = ''
   global ifile
   global data
   try:
      opts, args = getopt.getopt(argv,"hi:r:",["interface=","ifile="])
   except getopt.GetoptError:
      print 'test.py -i <interface> -r <file>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'test.py -i <interface> -r <file>'
         sys.exit()
      elif opt in ("-i", "--interface"):
         interface = arg
      elif opt in ("-r", "--ifile"):
         ifile = arg
   #print 'Interface is ', interface
   #print 'file is ', ifile
   
   #print len(sys.argv)
   global bpf
   if(len(sys.argv)==4):
   	bpf=sys.argv[3]
   #print bpf
   return interface

if __name__ == "__main__":
	interface=main(sys.argv[1:])
	if not interface:
		sniff(offline= ifile,filter = bpf, prn = querysniff, store = 0)
	else:
		sniff(iface = interface,filter = bpf, prn = querysniff, store = 0)
	print "\nShutting Down..."

