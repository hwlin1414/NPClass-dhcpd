#!/usr/bin/env python
#-*- coding:utf-8 -*-

import argparse
import socket
import random
import struct
import dhcp
import time

BUFSIZ = 4096
myaddr = '192.168.1.1'
pools = (
    ({'circuit': 'u5566a'}, {
        'ip': ('140.123.239.230',),
        'options': {
            dhcp.OPTION_NETMASK: '255.255.255.0',
            dhcp.OPTION_ROUTERS: ('140.123.239.250', ),
            dhcp.OPTION_DNS_SERVERS: ('168.95.1.1', '8.8.8.8'),
            dhcp.OPTION_LEASE_TIME: 7200
        }
    }),
    ({'circuit': 'u5566b'}, {
        'ip': ('140.123.239.231',),
        'options': {
            dhcp.OPTION_NETMASK: '255.255.255.0',
            dhcp.OPTION_ROUTERS: ('140.123.239.250', ),
            dhcp.OPTION_DNS_SERVERS: ('168.95.1.1', '8.8.8.8'),
            dhcp.OPTION_LEASE_TIME: 7200
        }
    }),
    ({'mac': 'aa:aa:aa:aa:aa:aa'}, {
        'ip': ('140.123.101.101',),
        'options': {
            dhcp.OPTION_NETMASK: '255.255.255.0',
            dhcp.OPTION_ROUTERS: ('140.123.101.250', ),
            dhcp.OPTION_DNS_SERVERS: ('168.95.1.1', '8.8.8.8'),
            dhcp.OPTION_LEASE_TIME: 600
        }
    }),
    ({'mac': 'bb:bb:bb:bb:bb:bb'}, {
        'ip': ('140.123.101.102',),
        'options': {
            dhcp.OPTION_NETMASK: '255.255.255.0',
            dhcp.OPTION_ROUTERS: ('140.123.101.250', ),
            dhcp.OPTION_DNS_SERVERS: ('168.95.1.1', '8.8.8.8'),
            dhcp.OPTION_LEASE_TIME: 600
        }
    }),
    ({}, {
        'ip': ('192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103'),
        'options': {
            dhcp.OPTION_NETMASK: '255.255.255.0',
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
            p = None
            for pool in pools:
                match = True
                for cond in pool[0]:
                    if cond == 'mac':
                        mac = pool[0][cond].replace(':', '').replace('.', '')
                        if packet.chaddr != mac:
                            match = False
                            break
                    elif cond == 'circuit':
                        opt82 = packet.getopt(dhcp.OPTION_RELAY_AGENT)
                        if opt82 is None or opt82.arg != pool[0][cond]:
                            match = False
                            break
                if match == True:
                    p = pool
                    break
            if p is None:
                print "No pool available!"
                continue
            flag = False
            for ip in p[1]['ip']:
                flag = True
                if ip not in using: break
                if using[ip]['time'] < int(time.time()): break
                flag = False
            if flag == False:
                print "Warning: No IP available!"
            using[ip] = {'time': int(time.time()) + args['lease'], 'xid': packet.xid}
            options = []
            options.append(dhcp.dhcp_option(dhcp.OPTION_SERVER_IDENTIFIER, myaddr))
            opts = p[1]['options']
            for opt in opts:
                options.append(dhcp.dhcp_option(opt, opts[opt]))
            pkt = dhcp.dhcp_packet(opt53 = dhcp.OPT53_OFFER, yiaddr = ip, siaddr = myaddr, mac = packet.chaddr, options = options, xid = packet.xid)
            if args['debug']:
                print "replying..."
                print pkt
            sock.sendto(pkt.raw(), ('<broadcast>', 68))
        elif packet.opt53 == dhcp.OPT53_REQUEST:
            for u in using:
                if using[u]['xid'] == packet.xid and using[u]['time'] > int(time.time()):
                    pkt = dhcp.dhcp_packet(opt53 = dhcp.OPT53_ACK, yiaddr = u, siaddr = myaddr, mac = packet.chaddr, options = options, xid = packet.xid)
                    if args['debug']:
                        print "replying..."
                        print pkt
                    sock.sendto(pkt.raw(), ('<broadcast>', 68))
                    break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DHCP Client')
    parser.add_argument('--debug', action='store_true', help='debug mode')
    parser.add_argument('--lease', type=int, help='ip lease time', default=3600)
    args = vars(parser.parse_args())
    if args['debug']:
        print("dhcp server start with args: ")
        print(args)
    main(args)
