from tabnanny import verbose
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

def request_handler(local_buffer, remote_host, remote_port):
    # perform packet modifications
    
    class Request(object):
        def __init__(self, verb, *args):
            self.verb = verb
            self.args = [str(x) for x in args]
    
    # dummy packet
    # send(IP(dst = remote_host)/ICMP())
    # send(Ether()/IP(dst = local_buffer.getsockname()[0], ttl =(1,1)), iface="eth0")
    send(IP(dst = remote_host, ttl = (1,1))/TCP(flags = "S", sport = RandShort(), dport = remote_port)/Raw(""))

    # splitting 
    fragsize = 500
    # bufsize = local_buffer.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    buffsize = len(local_buffer)
    fragsize = (fragsize + 7) // 8 * 8
    
    if(buffsize > fragsize):
        print(local_buffer)
        
        s = [local_buffer.decode("utf-8")[i:i+1] for i in range(0, len(local_buffer), 1)]

        if len(s) == 2:
            req_str = s[0]
            local_buffer = s[1]
            req_lst = [req_str[j:j+1] for j in range(0, len(req_lst), 1)]
            local_buffer = Request(req_lst[0], *req_lst[1:])
        # data = local_buffer
        # local_buffer += data
    return local_buffer

def response_handler(buffer):
    # perform packet modifications
    
    return buffer

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
            
            local_buffer_list = []
            local_buffer_list = request_handler(local_buffer, remote_host, remote_port)
            
            remote_socket.send(bytes(local_buffer_list))    
            print("[==>] Sent to remote %d bytes." % len(local_buffer_list))

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
    # nfqueue.listen(30)
    
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
    
    try:
        server_loop(local_host, local_port, remote_host, remote_port, receive_first)

    except KeyboardInterrupt:
        print('')
        # print("Flushing iptables")
        # os.system('iptables -F')
        # os.system('iptables -X')


# iptables = "iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1"
# print("Adding iptable rules : ")
# print(iptables)
# os.system(iptables)

if __name__ == '__main__':
    main()