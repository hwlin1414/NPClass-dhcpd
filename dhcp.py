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

dhcp_struct = struct.Struct(DHCP_HEADER_FORMAT)

def dhcp_option_from(raw):
    opt = ord(raw[0])
    if opt == 0: return (1, None)
    elif opt == 255: return (0, None)
    leng = ord(raw[1])
    value = raw[2:leng+2]
    if opt in (OPTION_MESSAGE_TYPE, ):
        return (leng + 2, dhcp_option(opt, ord(value)))
    elif opt in (OPTION_NETMASK, OPTION_SERVER_IDENTIFIER, OPTION_REQUESTED_ADDRESS):
        return (leng + 2, dhcp_option(opt, socket.inet_ntoa(value)))
    elif opt in (OPTION_ROUTERS, OPTION_NTP_SERVERS, OPTION_DNS_SERVERS):
        iplist = []
        for off in xrange(0, leng/4):
            iplist +=  [socket.inet_ntoa(value[off*4:off*4+4])]
        return (leng + 2, dhcp_option(opt, iplist))
    elif opt in (OPTION_LEASE_TIME, OPTION_RENEW_TIME, OPTION_REBIND_TIME):
        return (leng + 2, dhcp_option(opt, struct.unpack("!I", value)[0]))
    else:
        return (leng + 2, dhcp_option(opt, value))

class dhcp_option(object):
    def __init__(self, opt, arg):
        self.opt = opt
        self.arg = arg
    def __str__(self):
        return ("\t[options: %s, arg: %s]\n" % (OPTION[self.opt], self.arg))
    def raw(self):
        packet = ''
        if self.opt in (OPTION_MESSAGE_TYPE, ):
            packet += (struct.pack("!3B", self.opt ,1,self.arg))
        elif self.opt in (OPTION_NETMASK, OPTION_SERVER_IDENTIFIER, OPTION_REQUESTED_ADDRESS):
            packet += (struct.pack("!2B", self.opt, 4)+socket.inet_aton(self.arg))
        elif self.opt in (OPTION_ROUTERS, OPTION_NTP_SERVERS, OPTION_DNS_SERVERS):
            if len(self.arg) == 0: return ''
            packet += (struct.pack("!2B", self.opt, 4*len(self.arg)))
            for address in self.arg:
                packet += socket.inet_aton(address)
        elif self.opt in [OPTION_LEASE_TIME, OPTION_RENEW_TIME, OPTION_REBIND_TIME]:
            packet += struct.pack("!2BI", self.opt, 4, self.arg)
        else:
            packet += (struct.pack("!2B", self.opt, len(self.arg))+self.arg)
        return packet

def dhcp_packet_from(raw):
    if len(raw) < DHCP_HEADER_LENGTH:
        print "%d:%d" % (len(raw), DHCP_HeADER_LENGTH)
        return None
    if raw[DHCP_HEADER_LENGTH:DHCP_HEADER_LENGTH+4] != MAGIC_COOKIE:
        print("Magic Cookie Error!")
        return None
    header = dhcp_struct.unpack(raw[:DHCP_HEADER_LENGTH])
    offset = DHCP_HEADER_LENGTH+4
    options = []
    while offset < len(raw):
        (leng, option) = dhcp_option_from(raw[offset:])
        if leng == 0: break
        offset += leng
        if option.opt == OPTION_MESSAGE_TYPE:
            opt53 = option.arg
        else:
            options.append(option)
    return dhcp_packet(opt53=opt53, htype=header[1],
        hlen=header[2], hops=header[3],
        xid=header[4], secs=header[5],
        broadcast=True if header[6]==1<<15 else False,
        ciaddr=socket.inet_ntoa(header[7]),
        yiaddr=socket.inet_ntoa(header[8]),
        siaddr=socket.inet_ntoa(header[9]),
        giaddr=socket.inet_ntoa(header[10]),
        mac=header[11][0:6].encode('hex'), sname=header[12],
        file=header[13], options=options)

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
        self.chaddr = mac
        self.options = options
    def getopt(self, opt):
        for option in self.options:
            if option.opt == opt: return option
        return None
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
            'chaddr': self.chaddr,
            'sname': self.sname,
            'file': self.file
        })
        for op in self.options:
            rep += str(op)
        return rep
    def raw(self):
        packet = dhcp_struct.pack(
            self.op, self.htype, self.hlen, self.hops,
            self.xid, self.secs, self.flags,
            socket.inet_aton(self.ciaddr),
            socket.inet_aton(self.yiaddr), 
            socket.inet_aton(self.siaddr), 
            socket.inet_aton(self.giaddr),
            self.chaddr.decode('hex'),
            self.sname,
            self.file
        )
        packet += MAGIC_COOKIE
        packet += dhcp_option(OPTION_MESSAGE_TYPE, self.opt53).raw()
        for op in self.options:
            packet += op.raw()
        packet += chr(OPTION_END)
        return packet
