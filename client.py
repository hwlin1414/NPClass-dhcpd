#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import socket
import random
import time
#import netifaces
import fcntl
import struct
import dhcp

BUFSIZ = 4096

def main(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, args['interface'])
    sock.bind( ("", 68) )
    sock.settimeout(5)

    options = []
    if args['circuit'] is not None:
        options.append(dhcp.dhcp_option(dhcp.OPTION_RELAY_AGENT, args['circuit']))
    packet = dhcp.dhcp_packet(opt53 = dhcp.OPT53_DISCOVER, mac = args['mac'], options = options)
    
    print "Sending DHCP Discover"
    if args['debug']: print packet
    sock.sendto(packet.raw(), ("<broadcast>", 67))

    print "Recieving DHCP Discover"
    try:
        (response, server) = sock.recvfrom(BUFSIZ)
        packet = dhcp.dhcp_packet_from(response)
    except socket.timeout:
        print "Timeout"
        return
    if args['debug']: print packet
    print ""

    for option in packet.options:
        if option.opt == dhcp.OPTION_REQUESTED_ADDRESS:
            print "Using IP Address: %s" % option.arg
    for option in packet.options:
        if option.opt == dhcp.OPTION_NETMASK:
            print "Using Netmask: %s" % option.arg
    for option in packet.options:
        if option.opt == dhcp.OPTION_ROUTERS:
            print "Using Routers: %s" % str(option.arg)
    for option in packet.options:
        if option.opt == dhcp.OPTION_DNS_SERVERS:
            print "Using DNS Server: %s" % str(option.arg)
    print ""

    print "Sending DHCP Request"
    if args['debug']: print packet
    packet = dhcp.dhcp_packet(opt53 = dhcp.OPT53_REQUEST, mac = args['mac'], options = options, xid = packet.xid)
    sock.sendto(packet.raw(), ("<broadcast>", 67))

    print "Recieving DHCP ACK"
    try:
        (response, server) = sock.recvfrom(BUFSIZ)
        packet = dhcp.dhcp_packet_from(response)
    except socket.timeout:
        print "Timeout"
        return
    if args['debug']: print packet

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DHCP Client')
    parser.add_argument('--mac', help='mac address')
    parser.add_argument('--rand-mac', action='store_true', help='mac address')
    parser.add_argument('--debug', action='store_true', help='debug mode')
    parser.add_argument('--circuit', help='mac address')
    parser.add_argument('interface', help='interface')
    args = vars(parser.parse_args())
    if args['rand_mac']:
        args['mac'] = ''.join(random.choice("abcdef0123456789") for _ in xrange(0,12))
    elif args['mac'] is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', args['interface'][:15]))
        args['mac'] = ''.join(['%02x' % ord(char) for char in info[18:24]])
        #args['mac'] = netifaces.ifaddresses(args['interface'])[netifaces.AF_LINK][0]['addr'].replace(":", "")
    if args['debug']:
        print("dhcp client start with args: ")
        print(args)
    main(args)
