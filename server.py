#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import socket
import random
import struct
import dhcp
import time

BUFSIZ = 4096

pool = (
    ('192.168.1.0', '255.255.255.0', {
        'ip': ('192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103'),
        'options': {
            dhcp.OPTION_ROUTERS: ('192.168.1.1', ),
            dhcp.OPTION_DNS_SERVERS: ('168.95.1.1', '8.8.8.8'),
            dhcp.OPTION_LEASE_TIME: 3600
        }
    }),
)

def main(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind( ("", 67) )
    #sock.settimeout(5)
    using = {}
    while True:
        (response, client) = sock.recvfrom(BUFSIZ)
        packet = dhcp.dhcp_packet_from(response)
        if packet is None: continue
        print "%s from %s" % (dhcp.OPT53[packet.opt53], str(client))
        if args['debug']: print packet
        if packet.opt53 == dhcp.OPT53_DISCOVER:
            p = pool[0]
            flag = False
            for ip in p[2]['ip']:
                flag = True
                if ip not in using: break
                if using[ip]['time'] < int(time.time()): break
                flag = False
            if flag == False:
                print "Warning: No IP available!"
            using[ip] = {'time': int(time.time()) + 3600, 'xid': packet.xid}
            options = []
            options.append(dhcp.dhcp_option(dhcp.OPTION_REQUESTED_ADDRESS, ip))
            options.append(dhcp.dhcp_option(dhcp.OPTION_NETMASK, p[1]))
            opts = p[2]['options']
            for opt in opts:
                options.append(dhcp.dhcp_option(opt, opts[opt]))
            pkt = dhcp.dhcp_packet(opt53 = dhcp.OPT53_OFFER, mac = packet.chaddr, options = options, xid = packet.xid)
            if args['debug']:
                print "replying..."
                print pkt
            sock.sendto(pkt.raw(), ('<broadcast>', 68))
        elif packet.opt53 == dhcp.OPT53_REQUEST:
            for u in using:
                if using[u]['xid'] == packet.xid and using[u]['time'] > int(time.time()):
                    pkt = dhcp.dhcp_packet(opt53 = dhcp.OPT53_ACK, mac = packet.chaddr, options = options, xid = packet.xid)
                    if args['debug']:
                        print "replying..."
                        print pkt
                    sock.sendto(pkt.raw(), ('<broadcast>', 68))
                    break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DHCP Client')
    parser.add_argument('--debug', action='store_true', help='debug mode')
    args = vars(parser.parse_args())
    #print("dhcp server start with args: ")
    #print(args)
    main(args)
