CSE508: Network Security, Spring 2016

Homework 4: DNS Packet Injection
-------------------------------------------------------------------------------

Submission deadline: 5/6/2016 11:59pm EDT
Submission through https://blackboard.stonybrook.edu

-------------------------------------------------------------------------------

Submitted By: Alpit Kumar Gupta
Solar ID: 110451714

-------------------------------------------------------------------------------
#################################
1) an on-path DNS packet injector

###Design & Strategy:
I have used Python scapy library to use DNS Injection.

--------------------------------------
Install scapy in ubuntu
sudo apt-get install python-scapy
--------------------------------------

Program takes maximum of four arguments:
a. Name of the python program: dnsinject.py
b. -i (interface): name of the interface for sniffing
c. -f (file name): name of the file which contains domain name & corresponding IP address in the form of key value pair.
                   I have used ConfigParser (RawConfigParser object) library which works as a key value pair storage.
				   This is an optional argument. If any DNS query packet conatins domain name belongs to the file,
				   DNSInjector would reply with its corresponding IP address stored in the file. Either domain name 
				   is not found in the file, or filename is not provided, DNSInjector would reply with its own local IP address.
d. bpffilter<exp>: This is also an optional argument. If provided in the form of one or more comma seperated IP addresses,
				   It will only target provided set of victims.


Core logic: Listen over provided interface in promiscous mode.
			Sniff only DNS query packet with UDP protocol and port 53.
			If bpf filter provided, filter packets using comma seperated Victim's IP addresses.
			If found, use scapy library to inject a new packet with-
				src ip equal to the captured destination ip
				destination ip equal to the captured src ip
				answer query (rdata) equal to either own local ip address or Ip from filename.
				set UDP packet with src port= dst port and dst port=src port.	
				set reply packet with A type record, ttl and other parameters.
			Keep on listening for further packets.
				
				   
###How to run & test the program:

	1. Simple injection command with answer ip= local ip address	
			./dnsinject.py -i ens33
			
	
	2. Injection command with ip mentioned in the file	
			./dnsinject.py -i ens33 -f filename
			
	3. Injection command along with the bpf filters
			./dnsinject.py -i ens33 192.168.88.134,192.168.88.135
			./dnsinject.py -i ens33 -f filename 192.168.88.134,192.168.88.135,8.8.8.8

	Above command sniff for DNS query packet and inject a new DNS forged reply to the src ip address.
		
	
***********************************************************************************************
###output:
		root@ubuntu:/home/alpit# ./dnsinject.py -i ens33 -f filename 192.168.88.135,192.168.88.134
		WARNING: No route found for IPv6 destination :: (no default route?)
		.Begin emission:
		.Finished to send 1 packets.
		*
		Received 3 packets, got 1 answers, remaining 0 packets

		Packet created and sent!
		.
		Sent 1 packets.
***********************************************************************************************	

Note: I have used ConfigParser configuration file to store the forged ip addresses for domain names.
I have attached the sample file with this submission which keeps data in the below format:
**********************************
[database]
www.facebook.com=1.1.1.1
www.google.com=2.2.2.2
.
.
.
**********************************


##########################################
2) a passive DNS poisoning attack detector

Program takes maximum of three arguments:
a. Name of the python program: dnsdetect.py
b. -i (interface for live sniffing) or -r (offline pcap file for sniffing)
c. bpffilter<exp>: If bpf filter is provided in the argument, then it will not receive 
				   all the packets, but only from given subnet. Example: "udp and port 53"

###Design & Strategy:
Detector part has been divided into two parts.

----------------
a. Live sniffing: I have written python sniffing code to sniff packets, apply bpf filter if provided.
				  It takes interface name as an argument to listen for DNS traffic in promiscous mode.
				  It uses a dictionary to store both the DNS query and reply packet values. When it sniff any DNS query
				  packet, it stores the DNS ID as key and '0' as the value. If it sniff any DNS reply packet with
				  any of the stored ID, it overrides the value with the reply IP value. if detector tool find any	
				  DNS reply again with the ID stored in the dictionary and value not equal to '0', it further compare
				  the stored value with the current reply IP, if it matches then it considers it as retransmission
				  happened, not forged response where as if the stored value is not equal to the current response IP,
				  then it consider as a DNS poisioning attempt and alert through printing appropriate message.
				  #######This is how i made sure the condition of false positive cases.#######

				  Note: I am keeping last 100 pending DNS query records for detection. Once any DNS Id is detected as
				  forged, it will be deleted from the dictionary. Also, if dictionary size reaches 100, i am clearing
				  the dictionary and starting it fresh.

How to run & test the program:
				  
				  Simple command for DNDetector:
						./dnsdetect.py -i ens33
				  
				  Command along with bpf filter:
						./dnsdetect.py -i ens33 "udp and port 53"
						If bpf filter is provided in the argument, then it will not receive 
						all the packets, but only from given subnet. Example: "udp and port 53" 


----------------
b. File sniffing: This detector code works for the offline network traces provided as pcap file.
				  It takes name of the pcap file as an argument and apply the same above logic based on the DNS ID and rdata.
				  If multiple DNS reply  packet with same ID has been found, it first checks the response IP values,
				  if all are same, then it considers it as retransmission happened scenario, else alert DNS poisoning through 
				  printing appropriate message.
				  
				  Note: I have also included mycap.pcap file in this submission which i used for testing this case.
				  This file has forged ip address either equal to local ip address (192.168.88.134) or from the file.
				  
How to run & test the program:

				Simple command for DNDetector using offline file: 
						./dnsdetect.py -r mycap.pcap
				
				Command along with bpf filter:
						./dnsdetect.py -i ens33 -r mycap.pcap "udp and port 53"
						If bpf filter is provided in the argument, then it will not receive 
						all the packets, but only from given subnet. Example: "udp and port 53"

						
***********************************************************************************************	
###Output:
	
		###interface detection
		
		root@ubuntu:/home/gupta# nslookup www.google.com 8.8.8.8
		Server:		8.8.8.8
		Address:	8.8.8.8#53

		Name:	www.google.com
		Address: 2.2.2.2 (IP address reply from input file)

		root@ubuntu:/home/gupta# nslookup www.facebook.com 8.8.8.8
		Server:		8.8.8.8
		Address:	8.8.8.8#53

		Name:	www.facebook.com
		Address: 1.1.1.1  (IP address reply from input file)

		root@ubuntu:/home/gupta# nslookup www.qq.com 8.8.8.8
		Server:		8.8.8.8
		Address:	8.8.8.8#53

		Name:	www.qq.com
		Address: 192.168.88.134 (MY VMware client box IP address)
		
		root@ubuntu:/home/gupta# nslookup www.yahoo.com 8.8.8.8
		Server:		8.8.8.8
		Address:	8.8.8.8#53

		Name:	www.yahoo.com
		Address: 192.168.88.134 (MY VMware client box IP address)
			
		root@ubuntu:/home/gupta# ./dnsdetect.py -i ens33 "udp and port 53"
		WARNING: No route found for IPv6 destination :: (no default route?)
		2016-05-07 09:57    DNS poisoning attempt
		TXID: 31450   Request: www.google.com.
		Answer1: 2.2.2.2
		Answer2: 216.58.195.132
		****************************************************************
		2016-05-07 09:58    DNS poisoning attempt
		TXID: 2918   Request: www.facebook.com.
		Answer1: 1.1.1.1
		Answer2: star-mini.c10r.facebook.com.
		****************************************************************
		2016-05-07 09:58    DNS poisoning attempt
		TXID: 54907   Request: www.qq.com.
		Answer1: 192.168.88.134
		Answer2: qq.com.edgesuite.net.
		****************************************************************
		2016-05-07 10:01    DNS poisoning attempt
		TXID: 13569   Request: www.yahoo.com.
		Answer1: 192.168.88.134
		Answer2: fd-fp3.wg1.b.yahoo.com.
		****************************************************************
		
		
	####File detection:
		
		root@ubuntu:/home/gupta# ./dnsdetect.py -r mycap.pcap "udp and port 53"WARNING: No route found for IPv6 destination :: (no default route?)
		2016-05-09 20:08    DNS poisoning attempt
		TXID: 229   Request: www.qq.com.
		Answer1: 192.168.88.134
		Answer2: qq.com.edgesuite.net.
		****************************************************************
		WARNING: DNS RR prematured end (ofs=111, len=111)
		WARNING: DNS RR prematured end (ofs=112, len=111)
		2016-05-09 20:08    DNS poisoning attempt
		TXID: 63871   Request: www.facebook.com.
		Answer1: star-mini.c10r.facebook.com.
		Answer2: 1.1.1.1
		****************************************************************
		2016-05-09 20:08    DNS poisoning attempt
		TXID: 58252   Request: www.google.com.
		Answer1: 2.2.2.2
		Answer2: 172.217.3.4
		****************************************************************
		2016-05-09 20:08    DNS poisoning attempt
		TXID: 53345   Request: www.sita.com.
		Answer1: 192.168.88.134
		Answer2: 88.86.109.120
		****************************************************************
		2016-05-09 20:08    DNS poisoning attempt
		TXID: 53974   Request: www.flipkart.com.
		Answer1: 192.168.88.134
		Answer2: flipkart.com.
		****************************************************************

***********************************************************************************************	

Note: I have screenshots for dnsinject and dnsdetect in the submission folder.


References:

1. https://en.wikipedia.org/wiki/DNS_spoofing
2. http://www.secdev.org/projects/scapy/doc/usage.html
3. http://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
4. http://www.tutorialspoint.com/python/
5. https://www.vmware.com/support/ws55/doc/ws_newguest_setup_simple_steps.html
6. https://www.concise-courses.com/security/wireshark-basics/

