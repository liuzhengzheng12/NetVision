import argparse
import sys
import socket
import random
import struct

from scapy.all import *
from scapy.fields import *
import readline


class INT_CNT(Packet):
    fields_desc = [ BitField("cnt", 0, 8)]

class INT_Label(Packet):
    fields_desc = [ BitField("ingress_port", 0, 16),
                    BitField("egress_port", 0, 16),
                    BitField("ingress_tstamp", 0, 48),
                    BitField("egress_tstamp", 0, 48),
                    BitField("tos", 0, 8)]



def sendProbes():
    iface = 'eth4'
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt /= IP(dst='10.0.0.100')
    pkt /= TCP(dport=0xffff)
    pkt /= INT_CNT(cnt=0)
    sendpfast(pkt, pps=100, loop=2000, file_cache=True, iface=iface)


if __name__ == '__main__':
    sendProbes()