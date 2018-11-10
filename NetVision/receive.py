#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import *
from scapy.fields import *
import readline

TYPE_SR = 0x1234;
TYPE_INT = 0x5678;

ETHER_LEN = 14 << 1
INT_LEN = 1 << 1
SW_LEN = 4 << 1
INGRESS_PORT_LEN = 2 << 1
EGRESS_PORT_LEN = 2 << 1
INGRESS_GTSTAMP_LEN = 6 << 1
EGRESS_GTSTAMP_LEN = 6 << 1
INGRESS_TSTAMP_LEN = 4 << 1
EGRESS_TSTAMP_LEN = 4 << 1
HOP_LATENCY_LEN = 4 << 1
ENQ_QDEPTH_LEN = 2 << 1
Q_OCCUPANCY_LEN = 2 << 1
LABEL_LEN = 36 << 1

def extract_metadata(hexstr):
    pos = ETHER_LEN
    int_label_length = int(hexstr[pos:pos+INT_LEN], 16)
    pos += INT_LEN

    sw_id = []
    ingress_port = []
    egress_port = []
    ingress_gtstamp = []
    egress_gtstamp = []
    ingress_tstamp = []
    egress_tstamp = []
    hop_latency = []
    enq_qdepth = []
    q_occupancy = []

    for i in range(int_label_length):
        sw_id.append(int(hexstr[pos:pos+SW_LEN], 16))

        pos += SW_LEN
        ingress_port.append(int(hexstr[pos:pos+INGRESS_PORT_LEN], 16))

        pos += INGRESS_PORT_LEN
        egress_port.append(int(hexstr[pos:pos+EGRESS_PORT_LEN], 16))

        pos += EGRESS_PORT_LEN
        ingress_gtstamp.append(int(hexstr[pos:pos+INGRESS_GTSTAMP_LEN], 16))

        pos += INGRESS_GTSTAMP_LEN
        egress_gtstamp.append(int(hexstr[pos:pos+EGRESS_GTSTAMP_LEN], 16))

        pos += EGRESS_GTSTAMP_LEN
        ingress_tstamp.append(int(hexstr[pos:pos+INGRESS_TSTAMP_LEN], 16))

        pos += INGRESS_TSTAMP_LEN
        egress_tstamp.append(int(hexstr[pos:pos+EGRESS_TSTAMP_LEN], 16))

        pos += EGRESS_TSTAMP_LEN
        hop_latency.append(int(hexstr[pos:pos+HOP_LATENCY_LEN], 16))

        pos += HOP_LATENCY_LEN
        enq_qdepth.append(int(hexstr[pos:pos+ENQ_QDEPTH_LEN], 16))

        pos += ENQ_QDEPTH_LEN
        q_occupancy.append(int(hexstr[pos:pos+Q_OCCUPANCY_LEN], 16))
        pos += Q_OCCUPANCY_LEN
        #print "%x, %x, %x, %x, %x, %x, %x, %x, %x, %x" \
        #% (sw_id, ingress_port, egress_port, ingress_gtstamp, egress_gtstamp, \
        #                      ingress_tstamp, egress_tstamp, hop_latency, enq_qdepth, q_occupancy)
        #sys.stdout.flush()

    print "%d %d %d %d" % (egress_tstamp[0]-ingress_gtstamp[-1], (egress_tstamp[0]-ingress_gtstamp[0]+egress_tstamp[4]-ingress_gtstamp[4])/2, (egress_tstamp[1]-ingress_gtstamp[1]+egress_tstamp[3]-ingress_gtstamp[3])/2, egress_tstamp[2]-ingress_gtstamp[2])
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
    iface = 'H11-eth0'
    #print "sniffing on %s" % iface
    #sys.stdout.flush()
    sniff(filter="ether proto 0x5678", iface = iface, prn=lambda x: handle_pkt(x))



if __name__ == '__main__':
    receiveProbes()
