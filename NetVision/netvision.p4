#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPv4 = 0x0800;
const bit<8>  TYPE_TCP  = 0x0006;
const bit<8>  TYPE_UDP  = 0x0011;
const bit<8>  TYPE_FWD  = 0x00f0;
const bit<8>  TYPE_TMY  = 0x00f1;

const bit<32> MAX_PORT_NUM = 1 << 10;

#define FWD_MAX_LABELS  20
#define TMY_MAX_LABELS  20

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header fwd_header_t {
    bit<8> label_cnt;
}

header fwd_label_t {
    bit<16> outport;
}

header tmy_header_t {
    bit<8> label_cnt;
}

header tmy_label_t {
    bit<16> switch_id;          // switch_id
    //bit<24> bitmap;             // metadata bitmap
    // switch metadata
    bit<8>  state;              // control_plane_state_version
    // ingress metadata
    bit<16> ingress_port;       // ingress_port_id
    bit<48> ingress_tstamp;     // ingress_timestamp
    bit<32> ingress_pkt_cnt;    // ingress_port_RX_pkt_count
    bit<32> ingress_byte_cnt;   // ingress_port_RX_byte_count
    bit<32> ingress_drop_cnt;   // ingress_port_RX_drop_count
    //bit<32> ingress_util;       // ingress_port_RX_utilization
    // egress metadata
    bit<16> egress_port;        // egress_port_id
    bit<48> egress_tstamp;      // egress_timestamp
    bit<32> egress_pkt_cnt;     // egress_port_TX_pkt_count
    bit<32> egress_byte_cnt;    // egress_port_TX_byte_count
    bit<32> egress_drop_cnt;    // egress_port_TX_drop_count
    //bit<32> egress_util;        // egress_port_TX_utilization
    // buffer metadata
    bit<32> enq_tstamp;         // enq_timestamp
    bit<19> enq_qdepth;         // enq_qdepth
    bit<32> hop_latency;        // deq_timedelta
    bit<19> q_occupancy;        // deq_qdepth
    // packet metadata
    bit<32> pkt_len;            // packet_length
    bit<32> inst_type;          // instance_type
}

struct metadata {
    bit<1> is_probe;            
    bit<8> fwd_label_cnt;
    bit<8> tmy_label_cnt;
    bit<8> tmy_value_cnt;
    tmy_label_t tmy_label;
    bit<32> ingress_pkt_cnt;
    bit<32> ingress_byte_cnt;
    bit<32> ingress_drop_cnt;
    bit<32> egress_pkt_cnt;
    bit<32> egress_byte_cnt;
    bit<32> egress_drop_cnt;
}

struct headers {
    ethernet_t                      ethernet;
    ipv4_t                          ipv4;
    tcp_t                           tcp;
    udp_t                           udp;
    fwd_header_t                    fwd_header;
    fwd_label_t[FWD_MAX_LABELS]     fwd_labels;
    tmy_header_t                    tmy_header;
    tmy_label_t[TMY_MAX_LABELS]     tmy_labels;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        meta.is_probe = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPv4: parse_ipv4;
            default  : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_FWD: parse_fwd_header;
            TYPE_TMY: parse_tmy_header;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_fwd_header {
        packet.extract(hdr.fwd_header);
        meta.is_probe = 1;
        meta.fwd_label_cnt = hdr.fwd_header.label_cnt;
        transition select(meta.fwd_label_cnt) {
            0      : parse_tmy_header;
            default: parse_fwd_label;
        }
    }

    state parse_fwd_label {
        packet.extract(hdr.fwd_labels.next);
        meta.fwd_label_cnt = meta.fwd_label_cnt - 1;
        transition select(meta.fwd_label_cnt) {
            0      : parse_tmy_header;
            default: parse_fwd_label;
        }
    }

    state parse_tmy_header {
        packet.extract(hdr.tmy_header);
        meta.is_probe = 1;
        meta.tmy_label_cnt = hdr.tmy_header.label_cnt;
        transition select(meta.tmy_label_cnt) {
            0      : accept;
            default: parse_tmy_label;
        }
    }

    state parse_tmy_label {
        packet.extract(hdr.tmy_labels.next);
        meta.tmy_label_cnt = meta.tmy_label_cnt - 1;
        transition select(meta.tmy_label_cnt) {
            0      : accept;
            default: parse_tmy_label;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_PORT_NUM) ingressPktCounter;
    register<bit<32>>(MAX_PORT_NUM) ingressByteCounter;
    register<bit<32>>(MAX_PORT_NUM) ingressDropCounter;

    action ingress_traffic_count() {
        ingressPktCounter.read(meta.ingress_pkt_cnt, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_pkt_cnt = meta.ingress_pkt_cnt + 1;
        ingressPktCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_pkt_cnt);

        ingressByteCounter.read(meta.ingress_byte_cnt, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_byte_cnt = meta.ingress_byte_cnt + standard_metadata.packet_length;
        ingressByteCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_byte_cnt);
    }

    action ingress_drop_count() {
        ingressDropCounter.read(meta.ingress_drop_cnt, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_drop_cnt = meta.ingress_drop_cnt + (bit<32>)standard_metadata.drop;
        ingressDropCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_drop_cnt);
    }

    action drop() {
        mark_to_drop();
    }
    
    action fwd_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.fwd_labels[0].outport;
        hdr.fwd_labels.pop_front(1);
        hdr.fwd_header.label_cnt = hdr.fwd_header.label_cnt - 1;
    }

    action fwd_complete() {
        hdr.fwd_header.setInvalid();
        hdr.ipv4.protocol = TYPE_TMY;
    }

    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        ingress_traffic_count();

        if (meta.is_probe == 0) {
            if (hdr.ethernet.etherType == TYPE_IPv4) {
                if (hdr.ipv4.ttl == 0) {
                    drop();
                }
                else {
                    ipv4_lpm.apply();
                }
            }
        }
        else {
            if (hdr.fwd_header.label_cnt == 0) {
                drop();
            }
            else {
                fwd_nhop();
                if (hdr.fwd_header.label_cnt == 0) {
                    fwd_complete();
                }
            }
        }

        ingress_drop_count();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_PORT_NUM) egressPktCounter;
    register<bit<32>>(MAX_PORT_NUM) egressByteCounter;
    register<bit<32>>(MAX_PORT_NUM) egressDropCounter;

    action egress_traffic_count() {
        egressPktCounter.read(meta.egress_pkt_cnt, (bit<32>)standard_metadata.egress_port);
        meta.egress_pkt_cnt = meta.egress_pkt_cnt + 1;
        egressPktCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_pkt_cnt);

        egressByteCounter.read(meta.egress_byte_cnt, (bit<32>)standard_metadata.egress_port);
        meta.egress_byte_cnt = meta.egress_byte_cnt + standard_metadata.packet_length;
        egressByteCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_byte_cnt);
    }

    action egress_drop_count() {
        egressDropCounter.read(meta.egress_drop_cnt, (bit<32>)standard_metadata.egress_port);
        meta.egress_drop_cnt = meta.egress_drop_cnt + (bit<32>)standard_metadata.drop;
        egressDropCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_drop_cnt);
    }

    action push_tmy_label() {
        hdr.tmy_header.label_cnt = hdr.tmy_header.label_cnt + 1;
        hdr.tmy_labels.push_front(1);
        meta.tmy_label.setValid();
    }

    action assign_tmy_label() {
        hdr.tmy_labels[0] = meta.tmy_label;
    }

    action tmy_label_update(bit<16> switch_id, bit<8> state) {
        push_tmy_label();
        // switch metadata
        meta.tmy_label.switch_id = switch_id;
        meta.tmy_label.state = state;
        // ingress metadata
        meta.tmy_label.ingress_port = (bit<16>)standard_metadata.ingress_port;
        meta.tmy_label.ingress_tstamp = standard_metadata.ingress_global_timestamp;
        meta.tmy_label.ingress_pkt_cnt = meta.ingress_pkt_cnt;
        meta.tmy_label.ingress_byte_cnt = meta.ingress_byte_cnt;
        meta.tmy_label.ingress_drop_cnt = meta.ingress_drop_cnt;
        // egress metadata
        meta.tmy_label.egress_port = (bit<16>)standard_metadata.egress_port;
        meta.tmy_label.egress_tstamp = standard_metadata.egress_global_timestamp;
        meta.tmy_label.egress_pkt_cnt = meta.egress_pkt_cnt;
        meta.tmy_label.egress_byte_cnt = meta.egress_byte_cnt;
        meta.tmy_label.egress_drop_cnt = meta.egress_drop_cnt;
        // buffer metadata
        meta.tmy_label.enq_tstamp = standard_metadata.enq_timestamp;
         meta.tmy_label.enq_qdepth = standard_metadata.enq_qdepth;
        meta.tmy_label.hop_latency = standard_metadata.deq_timedelta;
        meta.tmy_label.q_occupancy = standard_metadata.deq_qdepth;
        // packet metadata
        meta.tmy_label.pkt_len = standard_metadata.packet_length;
        meta.tmy_label.inst_type = standard_metadata.instance_type;

        assign_tmy_label();
    }

    table update_tmy_label {
        actions = {
            tmy_label_update;
        }
        size = 1;
    }

    apply {
        egress_traffic_count();

        if (meta.is_probe == 1) {
            update_tmy_label.apply();
        }

        egress_drop_count();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {  
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.fwd_header);
        packet.emit(hdr.fwd_labels);
        packet.emit(hdr.tmy_header);
        packet.emit(hdr.tmy_labels);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
