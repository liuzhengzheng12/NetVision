#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPv4 = 0x0800;
const bit<16> TYPE_SR = 0x1234;
const bit<16> TYPE_INT = 0x5678;

const bit<32> MAX_PORT_NUM = 1 << 10;

#define SR_MAX_LABELS 20
#define INT_MAX_LABELS 20

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

header sr_header_t {
    bit<8> label_cnt;
}

header sr_label_t {
    bit<16> outport;
}

header int_header_t {
    bit<8> label_cnt;
}

header int_label_t {
    bit<24> bitmap;             // metadata bitmap
    // switch metadata
    bit<16> switch_id;          // switch_id
    bit<8> state;               // control_plane_state_version
    // ingress metadata
    bit<16> ingress_port;       // ingress_port_id
    bit<32> ingress_tstamp;     // ingress_timestamp
    bit<32> ingress_pkt_cnt;    // ingress_port_RX_pkt_count
    bit<32> ingress_byte_cnt;   // ingress_port_RX_byte_count
    bit<32> ingress_drop_cnt;   // ingress_port_RX_drop_count
    bit<32> ingress_util;       // ingress_port_RX_utilization
    // egress metadata
    bit<16> egress_port;        // egress_port_id
    bit<32> egress_tstamp;      // egress_timestamp
    bit<32> egress_pkt_cnt;     // egress_port_TX_pkt_count
    bit<32> egress_byte_cnt;    // egress_port_TX_byte_count
    bit<32> egress_drop_cnt;    // egress_port_TX_drop_count
    bit<32> egress_util;        // egress_port_TX_utilization
    // buffer metadata
    bit<32> enq_tstamp;         // enq_timestamp
    bit<19> enq_qdepth;         // enq_qdepth
    bit<32> hop_latency;        // deq_timedelta
    bit<16> q_occupancy;        // deq_qdepth
    // packet metadata
    bit<32> pkt_len;            // packet_length
    bit<32> inst_type;          // instance_type
}

struct metadata {
    bit<1> probe;
    bit<8> sr_label_cnt;
    bit<8> int_label_cnt;
    bit<8> int_value_cnt;
    int_label_t int_label;
}

struct headers {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    tcp_t                       tcp;
    udp_t                       udp;
    sr_header_t                 sr_header;
    sr_label_t[SR_MAX_LABELS]   sr_labels;
    int_header_t                int_header;
    int_label_t[INT_MAX_LABELS] int_labels;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        meta.probe = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SR: parse_sr_stack;
            TYPE_IPv4: parse_ipv4;
            default: accept;
        }
    }

    state parse_sr_stack {
        packet.extract(hdr.sr_header);
        meta.probe = 1;
        meta.sr_label_cnt = hdr.sr_header.cnt;
        transition select(meta.sr_label_cnt) {
            0: parse_int_stack;
            default: parse_sr_label;
        }
    }

    state parse_sr_label {
        packet.extract(hdr.sr_labels.next);
        meta.sr_label_cnt = meta.sr_label_cnt - 1;
        transition select(meta.sr_label_cnt) {
            0: parse_int_stack;
            default: parse_sr_label;
        }
    }

    state parse_int_stack {
        packet.extract(hdr.int_header);
        meta.probe = 1;
        meta.int_label_cnt = hdr.int_header.cnt;
        transition select(meta.int_label_cnt) {
            0: parse_ipv4;
            default: parse_int_label;
        }
    }

    state parse_int_label {
        packet.extract(hdr.int_labels.next);
        meta.int_label_cnt = meta.int_label_cnt - 1;
        transition select(meta.int_label_cnt) {
            0: parse_ipv4;
            default: parse_int_label;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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

    counter(MAX_PORT_NUM, CounterType.packets_and_bytes) ingressCounter;

    action drop() {
        mark_to_drop();
    }
    
    action sr_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.sr_labels[0].outport;
        hdr.sr_labels.pop_front(1);
        hdr.sr_header.cnt = hdr.sr_header.cnt - 1;
    }

    action sr_complete() {
        hdr.sr_header.setInvalid();
        hdr.ethernet.etherType = TYPE_INT;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
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
         ingressCounter.count((bit<32>) standard_metadata.ingress_port);

        if (meta.probe==1) {
            if (hdr.sr_header.cnt!=0){
                sr_nhop();
                if (hdr.sr_header.cnt==0) {
                    sr_complete();
                }
            }
            else {
                drop();
            }
        }
        if (hdr.ethernet.etherType==TYPE_IPv4) {
            if (hdr.ipv4.ttl!=0) {
                ipv4_lpm.apply();
            }
            else {
                drop();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    counter(MAX_PORT_NUM, CounterType.packets_and_bytes) egressCounter;

    action push_int_label() {
        hdr.int_header.cnt = hdr.int_header.cnt + 1;
        hdr.int_labels.push_front(1);
        meta.int_label.setValid();
    }

    action assign_int_label() {
        hdr.int_labels[0] = meta.int_label;
    }

    action int_label_update(bit<32> switch_id) {
        push_int_label();

        meta.int_label.switch_id = switch_id;
        meta.int_label.ingress_port = (bit<16>)standard_metadata.ingress_port;
        meta.int_label.egress_port = (bit<16>)standard_metadata.egress_port;
        meta.int_label.ingress_gtstamp = standard_metadata.ingress_global_timestamp;
        meta.int_label.egress_gtstamp = standard_metadata.egress_global_timestamp;
        meta.int_label.ingress_tstamp = standard_metadata.enq_timestamp;
        meta.int_label.egress_tstamp = standard_metadata.enq_timestamp + standard_metadata.deq_timedelta;
        meta.int_label.hop_latency = standard_metadata.deq_timedelta;
        meta.int_label.enq_qdepth = (bit<16>)standard_metadata.enq_qdepth;
        meta.int_label.q_occupancy = (bit<16>)standard_metadata.deq_qdepth;

        assign_int_label();
    }

    table update_int_label {
        actions = {
            int_label_update;
        }
        size = 1;
    }

    apply {
        egressCounter.count((bit<32>) standard_metadata.egress_port);

        if (meta.probe==1) {
            update_int_label.apply();
        }
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
        packet.emit(hdr.sr_header);
        packet.emit(hdr.sr_labels);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_labels);
        packet.emit(hdr.ipv4);
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
