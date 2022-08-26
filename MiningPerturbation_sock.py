from scapy.all import *
from random import randint

from netfilterqueue import NetfilterQueue
import os
import sys
import socket
import threading
import time

HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

def hexdump(src, length = 16, show = True):
    if isinstance(src, bytes):
        src = src.decode()
    
    results = list()
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        printable = word.translate(HEX_FILTER)
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length * 3
        results.append(f'{i:04x}  {hexa:<{hexwidth}}  {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results

def receive_from(connection):
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except Exception as e:
        pass
        return buffer

def request_handler(buffer):
    # perform packet modifications
    
    return buffer

def response_handler(buffer):
    # perform packet modifications
    
    return buffer

def fragment(remote_host, buffer, fragsize=1480):
    # Fragment a big IP datagram
    frag_host = remote_host
    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in buffer:
        s = raw(p[frag_host].payload)
        nb = (len(s) + fragsize - 1) // fragsize

        for i in range(nb):
            q = p.copy()
            del(q[frag_host].payload)
            del(q[frag_host].chksum)
            del(q[frag_host].len)

            if i != nb - 1:
                q[frag_host].flags |= 1
            q[frag_host].frag += i * fragsize // 4
            r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
            r.overload_fields = p[frag_host].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

def callback_splitting(local_buffer, fragsize = 1480):
    data = local_buffer.get_data()

    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in data:
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

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    # dum_host, dum_port = client_socket.getsockname()

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
    
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>] Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)
            
            # dummy packet
            # send(IP(dst = dum_host)/ICMP())
            # send(Ether()/IP(dst = local_buffer.getsockname()[0], ttl =(1,1)), iface="eth0")
            send(IP(dst = remote_host)/TCP(flags = "S", sport = RandShort(), dport = remote_port)/Raw(""))

            # splitting
            
            local_buffer_list = []
            try:
                local_buffer_list = callback_splitting(local_buffer, 500)

            except KeyboardInterrupt:
                print('')

            local_buffer = request_handler(local_buffer)

            for i in range(len(local_buffer_list)):
                remote_socket.send(local_buffer_list[i])    
            print("[==>] Sent to remote "+ len(local_buffer_list) + " splitted packets.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")
        
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break

def print_and_accept(pkt):
    print(pkt)
    pkt.accept()

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, local_port))

    except Exception as e:
        print('problem on bind: %r' % e)

        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
        sys.exit()
    
    print("[*] Listening on %s:%d" % (local_host, local_port))
    server.listen(30)

    while True:
        client_socket, addr = server.accept()

        #print out the local connection information
        line = "> Received incoming connection from %s:%d" % (addr[0], addr[1])
        print(line)

        #start a thread to talk to the remote hosst
        proxy_thread = threading.Thread(
            target = proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport]", end = '')
        print("[remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    # try:
        server_loop(local_host, local_port, remote_host, remote_port, receive_first)

    # except KeyboardInterrupt:
    #     print("Flushing iptables")
    #     os.system('iptables -F')
    #     os.system('iptables -X')


# iptables = "iptables -I INPUT -d 192.168.126.0/24 -j NFQUEUE --queue-num 1"
# print("Adding iptable rules : ")
# print(iptables)
# os.system(iptables)

if __name__ == '__main__':
    main()