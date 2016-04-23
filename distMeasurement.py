#!/usr/bin/ python2.7

"""
EECS325 Project 2
Auth: Matthew Roseman | mrr77@case.edu

Code stolen from:
   "www.binarytides.com/raw-socket-programming-in-python-linux/"
"""

import socket, sys
from struct import *

def main():

    #  Create the raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                socket.IPPROTO_RAW)
    except (socket.error, msg):
        print ("Socket could not be created. Error Code: " + str(msg[0]) +
              "Message " + msg[1])
        sys.exit()

    source_ip = "192.168.1.101"
    dest_ip = "192.168.1.1"

    #  IP header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    #  this will be filled in later by kernal
    ip_tot_len = 0
    #  the id of this packet
    #  TODO change this
    ip_id = 54321 
    ip_frag_off = 0
    ip_ttl = 32
    ip_proto = socket.IPPROTO_TCP
    #  kernal will also fill in the correct checksum
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (version << 4) + ihl

    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                     ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, 
                     ip_daddr)

    #  TCP header fields
    #  source port
    tcp_source = 1234
    #  destination port
    tcp_dest = 1
    tcp_seq = 454
    tcp_ack_seq = 0 
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    #  maximum allowed window size
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + \
                (tcp_ack << 4) + (tcp_urg << 5)

    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                      tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)


if __name__ == '__main__':
    main()
