#!/usr/bin/ python2.7

"""
EECS325 Project 2
Auth: Matthew Roseman | mrr77@case.edu

Code stolen from:
   "https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your"
"""

import socket, sys, time
from struct import *

def main():

    output_barrier = "----------------------------------------"

    udp = socket.getprotobyname('udp')
    icmp = socket.getprotobyname('icmp')
    ttl = 32
    port = 33434

    #  create the sending socket (udp packets)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
    send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    #  create the receiving socket (icmp packets)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    #  set timeout to 2 seconds
    recv_sock.settimeout(2);
    recv_sock.bind(("", port))

    targets = open('targets.txt', 'r')

    #  read every target from the file targets
    for dest_name in targets:

        print (output_barrier)

        #  remove the newline character
        dest_name = dest_name.rstrip()
        dest_addr = socket.gethostbyname(dest_name)
        print ("Destination: " + dest_name + " " + dest_addr)

        #  used later to calculate RTT
        time_sent = time.clock()
        print ("start: " + str(time_sent))
        send_sock.sendto("", (dest_name, port))

        try:
            resp_data, resp_addr = recv_sock.recvfrom(512)

            resp_addr = resp_addr[0]
        except socket.error:
            pass
        #  used to calculate RTT
        time_recv = time.clock()
        print("end: " + str(time_recv))

        icmp_header = resp_data[20:28]
        type, code, checksum, p_id, sequence = unpack('bbHHh', icmp_header)
        print ("RTT: " + str(round((time_recv - time_sent) * 10000, 2)) + " msec")

        #  the data of the icmp
        icmp_body = resp_data[28:]
        print ("ICMP body length: " + str(len(icmp_body)) + " bytes")
        ip_ttl = unpack('b', icmp_body[8])
        ip_ttl = int(str(ip_ttl).strip("(), "))
        print ("TTL difference: " + str(ttl - ip_ttl))

    print (output_barrier + "\n")


if __name__ == '__main__':
    main()
