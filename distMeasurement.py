#!/usr/bin/ python2.7

"""
EECS325 Project 2
Auth: Matthew Roseman | mrr77@case.edu

Code stolen from:
   "https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your"
"""

import socket, sys, time
from struct import *

ICMP_ECHO_REQUEST = 8

def main():

    udp = socket.getprotobyname('udp')
    icmp = socket.getprotobyname('icmp')
    ttl = 32
    port = 33434

    #  create the sending socket (udp packets)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

    #  create the receiving socket (icmp packets)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    #  set timeout to 2 seconds
    recv_sock.settimeout(2);
    recv_sock.bind(("", port))

    targets = open('targets.txt', 'r')

    #  read every target from the file targets
    for dest_name in targets:
        #  remove the newline character
        dest_name = dest_name.rstrip()
        print (dest_name)
        dest_addr = socket.gethostbyname(dest_name)
        print (dest_addr)

        #  used later to calculate RTT
        packet = create_packet()
        time_sent = time.time()
        send_sock.sendto("", (dest_name, port))

        try:
            resp_data, resp_addr = recv_sock.recvfrom(512)
            #  used to calculate RTT
            time_recv = time.time()
            resp_addr = resp_addr[0]
        except socket.error:
            pass
        print (resp_addr)
        print (resp_data)
        print (''.join(format(ord(x), 'b') for x in resp_data))
        #  TODO: read the response datagram and get remaining ttl
        #  don't know why this section is the header and not the beginning  
        icmp_header = resp_data[20:28]
        type, code, checksum, p_id, sequence = unpack('bbHHh', icmp_header)
        print ("RTT: " + str((time_recv - time_sent) * 1000) + "msec")
        print ("ICMP type: " + str(type))
        print ("ICMP code: " + str(code))
        #  the data of the icmp
        icmp_body = resp_data[28:]
        print ("ICMP body length: " + str(len(icmp_body)))
        ip_ttl = unpack('b', icmp_body[8])
        print ("Datagram TTL: " + str(ip_ttl))


def create_packet(self):
    """
    Creates a new ICMP packet
    @return: returns the ICMP packet
    Code gotten from https://gist.github.com/pklaus/856268
    """
    #TODO change this
    id = 100
    header = pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = "Hello World" * 100
    packet_checksum = checksum(header + data)
    header = pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(packet_checksum),
                  id, 1)
    return header + data

def checksum(self, source_string):
    """
    Calculates the checksum of src
    @param: source_string the data to be checked
    @return: returns this checksum
    Code gotten from https://gist.github.com/pklaus/856268
    """
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1])*256+ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


if __name__ == '__main__':
    main()
