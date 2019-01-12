#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import *
from scapy.fields import *
import readline

PORT_INT = 0xffff

ETHER_LEN = 14 << 1
IP_LEN = 20 << 1
TCP_LEN = 20 << 1
INT_LEN = 1 << 1
INGRESS_PORT_LEN = 2 << 1
EGRESS_PORT_LEN = 2 << 1
INGRESS_GTSTAMP_LEN = 6 << 1
EGRESS_GTSTAMP_LEN = 6 << 1
TOS_LEN = 1 << 1

def extract_metadata(hexstr):
    pos = ETHER_LEN + IP_LEN + TCP_LEN
    int_label_length = int(hexstr[pos:pos+INT_LEN], 16)
    pos += INT_LEN

    ingress_port = []
    egress_port = []
    ingress_gtstamp = []
    egress_gtstamp = []

    time_interval = 0

    for i in range(int_label_length):
        ingress_port.append(int(hexstr[pos:pos+INGRESS_PORT_LEN], 16))

        pos += INGRESS_PORT_LEN
        egress_port.append(int(hexstr[pos:pos+EGRESS_PORT_LEN], 16))

        pos += EGRESS_PORT_LEN
        ingress_gtstamp.append(int(hexstr[pos:pos+INGRESS_GTSTAMP_LEN], 16))

        pos += INGRESS_GTSTAMP_LEN
        egress_gtstamp.append(int(hexstr[pos:pos+EGRESS_GTSTAMP_LEN], 16))
        pos += (EGRESS_GTSTAMP_LEN + TOS_LEN)

        time_interval += (egress_gtstamp[-1] - ingress_gtstamp[-1])

    print "%d %d %f" % (egress_gtstamp[0]-ingress_gtstamp[-1], time_interval, time_interval * 1.0 / (egress_gtstamp[0]-ingress_gtstamp[-1]))
    sys.stdout.flush()


def handle_pkt(pkt):
    #print "got the probe"
    #pkt.show()
    str = hexdump(pkt, dump=True)
    #print str
    str_list = str.split('\n')
    hex_str = ""
    for str in str_list:
        p1 = str.find(' ')
        p2 = str.find(' ', p1+2)
        hex_str += str[p1+2:p2]
    extract_metadata(hex_str)
    sys.stdout.flush()


def receiveProbes():
    iface = 'enp4s0'
    #print "sniffing on %s" % iface
    #sys.stdout.flush()
    sniff(filter="tcp dst port 0xffff", iface = iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    receiveProbes()
