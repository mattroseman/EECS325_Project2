#!/usr/bin/ python2.7

"""
EECS325 Project 2
Auth: Matthew Roseman | mrr77@case.edu

Code stolen from:
   "https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your"
"""

import socket, sys
from struct import *

def main():

    targets = open('targets.txt', 'r')
    #  read every target from the file targets
    for dest_name in targets:
        #  remove the newline character
        dest_name = dest_name.rstrip()
        dest_addr = socket.gethostbyname(dest_name)

        udp = socket.getprotobyname('udp')
        icmp = socket.getprotobyname('icmp')
        ttl = 32
        port = 33434

        #  create the sending socket (udp packets)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        #  set the ttl of the socket
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        #  create the receiving socket (icmp packets)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

        recv_sock.bind(("", port))
        send_sock.sendto("", (dest_name, port))

        try:
            _, resp_addr = recv_sock.recvfrom(512)
            resp_addr = resp_addr[0]
            print (resp_addr)
        except socket.error:
            pass


if __name__ == '__main__':
    main()
