#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import socket
import random
import time
import uuid
import struct
import dhcp_packet

BUFSIZ = 4096

def main(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind( ("", 68) )
    sock.settimeout(5)

    packet = dhcp_packet.dhcp_packet(opt53 = dhcp_packet.OPT53_DISCOVER, mac = args['mac'])
    
    print "Sending DHCP Discover"
    print packet
    sock.sendto(packet.raw(), ("<broadcast>", 67))
    try:
        response = sock.recv(BUFSIZ)
    except socket.timeout:
        print "Timeout"
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DHCP Client')
    parser.add_argument('--mac', help='mac address')
    parser.add_argument('interface', nargs='?', help='interface')
    args = vars(parser.parse_args())
    if args['interface'] is None and args['mac'] is None:
        args['mac'] = ''.join(random.choice("abcdef0123456789") for _ in xrange(0,12))
    elif args['mac'] is None:
        args['mac'] = hex(uuid.getnode())[2:].zfill(12)
    print("dhcp client start with args: ")
    print(args)
    main(args)
