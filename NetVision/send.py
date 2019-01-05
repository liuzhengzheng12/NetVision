#!/usr/bin/env python
# from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.fields import BitField
from scapy.packet import Packet
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sendp

PORT_FWD = 0xffff
PORT_TMY_DATA = 0xfffe


class FWD_Header(Packet):
    fields_desc = [BitField('label_cnt', 0, 8)]


class FWD_Label(Packet):
    fields_desc = [BitField('outport', 0, 8)]


class TMY_INST_Header(Packet):
    fields_desc = [BitField('label_cnt', 0, 8)]


class TMY_INST_Label(Packet):
    fields_desc = [BitField('switch_id', 0, 16),
                   BitField('bit_state', 0, 1),
                   BitField('bit_ingress_port', 0, 1),
                   BitField('bit_ingress_tstamp', 0, 1),
                   BitField('bit_ingress_pkt_cnt', 0, 1),
                   BitField('bit_ingress_byte_cnt', 0, 1),
                   BitField('bit_ingress_drop_cnt', 0, 1),
                   BitField('bit_egress_port', 0, 1),
                   BitField('bit_egress_tstamp', 0, 1),
                   BitField('bit_egress_pkt_cnt', 0, 1),
                   BitField('bit_egress_byte_cnt', 0, 1),
                   BitField('bit_egress_drop_cnt', 0, 1),
                   BitField('bit_enq_tstamp', 0, 1),
                   BitField('bit_enq_qdepth', 0, 1),
                   BitField('bit_deq_timedelta', 0, 1),
                   BitField('bit_deq_qdepth', 0, 1),
                   BitField('bit_pkt_len', 0, 1),
                   BitField('bit_inst_type', 0, 1),
                   BitField('bit_reserved', 0, 7)]


def sendProbes():
    dstAddr = "10.0.2.22"
    iface = "lo0"
    print "sending probes on interface %s to %s" % (iface, dstAddr)

    port_list = [4, 2, 4, 1, 1]
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IP() / TCP(dport=PORT_FWD)
    pkt /= FWD_Header(label_cnt=len(port_list))
    for port in port_list:
        pkt /= FWD_Label(outport=port)

    pkt /= TMY_INST_Header(label_cnt=1)
    pkt /= TMY_INST_Label(switch_id=1, bit_state=1)
    pkt.show()
    # sendpfast(pkt, pps=2, loop=200, file_cache=True, iface=iface)
    sendp(pkt, iface=iface)


if __name__ == '__main__':
    sendProbes()
