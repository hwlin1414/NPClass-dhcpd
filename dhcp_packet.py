#!/usr/bin/env python
#-*- coding:utf-8 -*-

import struct
import socket
import random

# op 
OP_REQUEST = 1
OP_REPLY = 2
OP = {OP_REQUEST: 'REQUEST', OP_REPLY: 'REPLY'}

# magic cooke
MAGIC_COOKIE = "\x63\x82\x53\x63"

# options ( currently/willbe supported )
OPTION_PADDING = 0
OPTION_NETMASK = 1
OPTION_ROUTERS = 3 
OPTION_DNS_SERVERS = 6
OPTION_HOSTNAME = 12
OPTION_NTP_SERVERS = 42 
OPTION_REQUESTED_ADDRESS = 50
OPTION_LEASE_TIME = 51
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_IDENTIFIER = 54
OPTION_RENEW_TIME = 58
OPTION_REBIND_TIME = 59
OPTION_RELAY_AGENT = 82
OPTION_END = 255
OPTION = {
    OPTION_PADDING: 'OPTION_PADDING',
    OPTION_NETMASK: 'OPTION_NETMASK',
    OPTION_ROUTERS: 'OPTION_ROUTERS',
    OPTION_DNS_SERVERS: 'OPTION_DNS_SERVERS',
    OPTION_HOSTNAME: 'OPTION_HOSTNAME',
    OPTION_NTP_SERVERS: 'OPTION_NTP_SERVERS',
    OPTION_REQUESTED_ADDRESS: 'OPTION_REQUESTED_ADDRESS',
    OPTION_LEASE_TIME: 'OPTION_LEASE_TIME',
    OPTION_MESSAGE_TYPE: 'OPTION_MESSAGE_TYPE',
    OPTION_SERVER_IDENTIFIER: 'OPTION_SERVER_IDENTIFIER',
    OPTION_RENEW_TIME: 'OPTION_RENEW_TIME',
    OPTION_REBIND_TIME: 'OPTION_REBIND_TIME',
    OPTION_RELAY_AGENT: 'OPTION_RELAY_AGENT',
    OPTION_END: 'OPTION_END'
}

# Option 53
OPT53_DISCOVER = 1 
OPT53_OFFER = 2
OPT53_REQUEST = 3 
OPT53_DECLINE = 4
OPT53_ACK = 5 
OPT53_NACK = 6
OPT53_RELEASE = 7
OPT53_INFORM = 8

OPT53 = {
    OPT53_DISCOVER: 'OPT53_DISCOVER',
    OPT53_OFFER: 'OPT53_OFFER',
    OPT53_REQUEST: 'OPT53_REQUEST',
    OPT53_DECLINE: 'OPT53_DECLINE',
    OPT53_ACK: 'OPT53_ACK',
    OPT53_NACK: 'OPT53_NACK',
    OPT53_RELEASE: 'OPT53_RELEASE',
    OPT53_INFORM: 'OPT53_INFORM'
}

# Misc
DHCP_HEADER_FORMAT = "!4B1I2H4s4s4s4s16s64s128s"
DHCP_HEADER_LENGTH = struct.calcsize(DHCP_HEADER_FORMAT)

__dhcp_struct__ = struct.Struct(DHCP_HEADER_FORMAT)

def dhcp_option_from(raw):
    pass

class dhcp_option(object):
    def __init__(self, opt, arg):
        self.opt = opt
        self.arg = arg
    def __str__(self):
        return ("\t[options: %s, arg: %s]\n" % (OPTION[self.opt], self.arg))
    def raw(self):
        packet = ''
        if code in (OPTION_MESSAGE_TYPE, ):
            packet += (struct.pack("!3B", code ,1,value))
        elif code in (OPTION_NETMASK, OPTION_SERVER_IDENTIFIER, OPTION_REQUESTED_ADDRESS):
            packet += (struct.pack("!2B", code, 4)+socket.inet_aton(value))
        elif code in (OPTION_ROUTERS, OPTION_NTP_SERVERS, OPTION_DNS_SERVERS):
            if len(value) == 0: return ''
            packet += (struct.pack("!2B", code, 4*len(value)))
            for address in value:
                packet += socket.inet_aton(address)
        elif code in [OPTION_LEASE_TIME, OPTION_RENEW_TIME, OPTION_REBIND_TIME]:
            packet += struct.pack("!2BI", code, 4, value)
        else:
            packet += (struct.pack("!2B", code, len(value))+value)
        return packet

def dhcp_packet_from(raw):
    pass

class dhcp_packet(object):
    def __init__(self, opt53, mac, hlen=6, htype=1, hops=0, secs=0, xid=None, broadcast=True, 
            ciaddr=None, yiaddr=None, siaddr=None, giaddr=None, sname="", file="", options=[]):
        self.options = []
        if opt53 in (OPT53_DISCOVER, OPT53_REQUEST, OPT53_RELEASE, OPT53_INFORM):
            self.op = OP_REQUEST
        elif opt53 in (OPT53_OFFER, OPT53_DECLINE, OPT53_ACK, OPT53_NACK):
            self.op = OP_REPLY
        else:
            print opt53
            raise Exception("Unknown DHCP Message Type")

        if not xid:
            self.xid = random.SystemRandom().randrange(2**32)
        else: self.xid = xid

        self.opt53 = opt53

        self.hlen = hlen
        self.htype = htype
        self.hops = hops
        self.secs = secs
        self.flags = 1 << 15 if broadcast else 0
        self.sname = sname
        self.file = file

        self.ciaddr = "0.0.0.0" if not ciaddr else ciaddr
        self.yiaddr = "0.0.0.0" if not yiaddr else yiaddr
        self.siaddr = "0.0.0.0" if not siaddr else siaddr
        self.giaddr = "0.0.0.0" if not giaddr else giaddr
        self.chaddr = mac.decode('hex')
        self.options = options
    def __str__(self):
        rep = ("Message type: %(mtype)d (%(opt53)s)\n" % {
            'mtype': self.opt53,
            'opt53': OPT53[self.opt53]
        })
        rep += ("\t[op: %(op)s,  htype: %(htype)d, hlen: %(hlen)d, hops: %(hops)d]\n" % {
            'op': OP[self.op],
            'htype': self.htype,
            'hlen': self.hlen,
            'hops': self.hops
        })
        rep += ("\t[xid: %(xid)d, secs: %(secs)d, flags: %(flags)d]\n" % {
            'xid': self.xid,
            'secs': self.secs,
            'flags': self.flags
        })
        rep += ("\t[ciaddr: %(ciaddr)s, yiaddr:  %(yiaddr)s, siaddr: %(siaddr)s, giaddr: %(giaddr)s]\n" % {
            'ciaddr': self.ciaddr,
            'yiaddr': self.yiaddr,
            'siaddr': self.siaddr,
            'giaddr': self.giaddr
        })
        rep += ("\t[chaddr: %(chaddr)s, sname: \"%(sname)s\", file: \"%(file)s\"]\n" % {
            'chaddr': self.chaddr.encode('hex'),
            'sname': self.sname,
            'file': self.file
        })
        for op in self.options:
            rep += str(op)
        return rep
    def raw(self):
        packet = __dhcp_struct__.pack(
            self.op, self.htype, self.hlen, self.hops,
            self.xid, self.secs, self.flags,
            socket.inet_aton(self.ciaddr),
            socket.inet_aton(self.yiaddr), 
            socket.inet_aton(self.siaddr), 
            socket.inet_aton(self.giaddr),
            self.chaddr,
            self.sname,
            self.file
        )
        packet += MAGIC_COOKIE
        for op in self.options:
            packet += op.raw()
        packet += chr(OPTION_END)
        return packet
