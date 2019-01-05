#!/usr/bin/env python
# from scapy.all import *
from scapy.utils import hexdump
from scapy.sendrecv import sniff
import sys

PORT_FWD = 0xffff
PORT_TMY_DATA = 0xfffe

ETHER_LEN = 14 << 1
IP_LEN = 20 << 1
TCP_LEN = 20 << 1
UDP_LEN = 8 << 1
TMY_DATA_HEADER_LEN = 1 << 1
SW_ID_LEN = 2 << 1
BITMAP_LEN = 3 << 1
STATE_LEN = 1 << 1
INGRESS_PORT_LEN = 1 << 1
INGRESS_TSTAMP_LEN = 6 << 1
INGRESS_PKT_CNT_LEN = 4 << 1
INGRESS_BYTE_CNT_LEN = 4 << 1
INGRESS_DROP_CNT_LEN = 4 << 1
EGRESS_PORT_LEN = 1 << 1
EGRESS_TSTAMP_LEN = 6 << 1
EGRESS_PKT_CNT_LEN = 4 << 1
EGRESS_BYTE_CNT_LEN = 4 << 1
EGRESS_DROP_CNT_LEN = 4 << 1
ENQ_TSTAMP_LEN = 4 << 1
ENQ_QDEPTH_LEN = 2 << 1
DEQ_TIMEDELTA_LEN = 4 << 1
DEQ_QDEPTH_LEN = 2 << 1
PKT_LEN_LEN = 4 << 1
INST_TYPE_LEN = 4 << 1


def extract_metadata(hexstr):
    pass


def handle_pkt(pkt):
    # print "got the probe"
    pkt.show()
    str = hexdump(pkt, dump=True)
    print str
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
    # print "sniffing on %s" % iface
    # sys.stdout.flush()
    sniff(filter="tcp dst port 0xfffe", iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    receiveProbes()
