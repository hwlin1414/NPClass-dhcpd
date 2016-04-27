#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import socket
import random
import time
import netifaces
import struct
import dhcp

BUFSIZ = 4096

def main(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind( ("", 68) )
    sock.settimeout(5)

    packet = dhcp.dhcp_packet(opt53 = dhcp.OPT53_DISCOVER, mac = args['mac'])
    
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
    parser.add_argument('--rand-mac', action='store_true', help='mac address')
    parser.add_argument('interface', help='interface')
    args = vars(parser.parse_args())
    if args['rand_mac']:
        args['mac'] = ''.join(random.choice("abcdef0123456789") for _ in xrange(0,12))
    elif args['mac'] is None:
        args['mac'] = netifaces.ifaddresses(args['interface'])[netifaces.AF_LINK][0]['addr'].replace(":", "")
    print("dhcp client start with args: ")
    print(args)
    main(args)
