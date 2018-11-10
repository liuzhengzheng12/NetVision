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

class SR_Header(Packet):
   fields_desc = [ BitField("cnt", 0, 8)]


class SR_Label(Packet):
    fields_desc = [BitField("outport", 0, 16)]


class INT_Header(Packet):
    fields_desc = [ BitField("cnt", 0, 8)]


class INT_Label(Packet):
    fields_desc = [ BitField("switch_id", 0, 32),
                    BitField("ingress_port", 0, 16),
                    BitField("egress_port", 0, 16),
                    BitField("ingress_gtstamp", 0, 48),
                    BitField("egress_gtstamp", 0, 48),
                    BitField("ingress_tstamp", 0, 32),
                    BitField("egress_tstamp", 0, 32),
                    BitField("hop_latency", 0, 32),
                    BitField("enq_qdepth", 0, 16),
                    BitField("q_occupancy", 0, 16)]


def sendProbes():
    dstAddr = "10.0.2.22"
    iface = "H11-eth0"
    print "sending probes on interface %s to %s" % (iface, dstAddr)

    port_list = [4, 2, 4, 1, 1]
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_SR);
    pkt = pkt / SR_Header(cnt=len(port_list))
    for port in port_list:
        pkt = pkt / SR_Label(outport=port)

    pkt = pkt / INT_Header(cnt=0) / IP(dst=dstAddr) / TCP(dport=4321, sport=1234)
    pkt.show()
    sendpfast(pkt, pps=2, loop=200, file_cache=True, iface=iface)
    #sendp(pkt, iface=iface)


if __name__ == '__main__':
    sendProbes()
