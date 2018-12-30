#include <core.p4>
#include <v1model.p4>

// ethernet.etherType
const bit<16> TYPE_IPv4 = 0x0800;
// ipv4.protocol
const bit<8>  TYPE_TCP  = 0x0006;
const bit<8>  TYPE_UDP  = 0x0011;
// tcp or udp .dstPort
const bit<16> PORT_FWD  = 0xffff;
const bit<16> PORT_TMY_DATA  = 0xfffe;

const bit<32> MAX_PORT_NUM = 1 << 8;

#define FWD_MAX_LABELS  100
#define TMY_MAX_LABELS  100

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
    bit<8> outport;
}

header tmy_inst_header_t {
    bit<8> label_cnt;
}

header tmy_inst_label_t {
    bit<16> switch_id;          // switch_id
    // metadata bitmap
    bit<1>  bit_state;
    bit<1>  bit_ingress_port;
    bit<1>  bit_ingress_tstamp;
    bit<1>  bit_ingress_pkt_cnt;
    bit<1>  bit_ingress_byte_cnt;
    bit<1>  bit_ingress_drop_cnt;
    bit<1>  bit_egress_port;
    bit<1>  bit_egress_tstamp;
    bit<1>  bit_egress_pkt_cnt;
    bit<1>  bit_egress_byte_cnt;
    bit<1>  bit_egress_drop_cnt;
    bit<1>  bit_enq_tstamp;
    bit<1>  bit_enq_qdepth;
    bit<1>  bit_deq_timedelta;
    bit<1>  bit_deq_qdepth;
    bit<1>  bit_pkt_len;
    bit<1>  bit_inst_type;
    bit<7>  bit_reserved;
}

header tmy_data_header_t {
    bit<8> label_cnt;
}

header switch_id_t {
    bit<16> switch_id;          // switch_id
}

header bitmap_t {
    // metadata bitmap
    bit<1>  bit_state;
    bit<1>  bit_ingress_port;
    bit<1>  bit_ingress_tstamp;
    bit<1>  bit_ingress_pkt_cnt;
    bit<1>  bit_ingress_byte_cnt;
    bit<1>  bit_ingress_drop_cnt;
    bit<1>  bit_egress_port;
    bit<1>  bit_egress_tstamp;
    bit<1>  bit_egress_pkt_cnt;
    bit<1>  bit_egress_byte_cnt;
    bit<1>  bit_egress_drop_cnt;
    bit<1>  bit_enq_tstamp;
    bit<1>  bit_enq_qdepth;
    bit<1>  bit_deq_timedelta;
    bit<1>  bit_deq_qdepth;
    bit<1>  bit_pkt_len;
    bit<1>  bit_inst_type;
    bit<7>  bit_reserved;
}

// switch metadata
header state_t {
    bit<8>  state;              // control_plane_state_version
}

// ingress metadata
header ingress_port_t {
    bit<8> ingress_port;        // ingress_port_id
}

header ingress_tstamp_t {
    bit<48> ingress_tstamp;     // ingress_timestamp
}

header ingress_pkt_cnt_t {
    bit<32> ingress_pkt_cnt;    // ingress_port_RX_pkt_count
}

header ingress_byte_cnt_t {
    bit<32> ingress_byte_cnt;   // ingress_port_RX_byte_count
}

header ingress_drop_cnt_t {
    bit<32> ingress_drop_cnt;   // ingress_port_RX_drop_count
}

// egress metadata
header egress_port_t {
    bit<8> egress_port;        // egress_port_id
}

header egress_tstamp_t {
    bit<48> egress_tstamp;     // egress_timestamp
}

header egress_pkt_cnt_t {
    bit<32> egress_pkt_cnt;    // egress_port_TX_pkt_count
}

header egress_byte_cnt_t {
    bit<32> egress_byte_cnt;   // egress_port_TX_byte_count
}

header egress_drop_cnt_t {
    bit<32> egress_drop_cnt;   // egress_port_TX_drop_count
}

// buffer metadata
header enq_tstamp_t {
    bit<32> enq_tstamp;         // enq_timestamp
}

header enq_qdepth_t {
    bit<16> enq_qdepth;         // enq_qdepth
}

header deq_timedelta_t {
    bit<32> deq_timedelta;      // deq_timedelta
}

header deq_qdepth_t {
    bit<16> deq_qdepth;        // deq_qdepth
}

// packet metadata
header pkt_len_t {
    bit<32> pkt_len;           // packet_length
}

header inst_type_t {
    bit<32> inst_type;         // instance_type
}

struct metadata {
    bit<1>                              is_probe;    
    bit<1>                              is_switch;        
    bit<8>                              fwd_label_cnt;
    bit<8>                              tmy_inst_label_cnt;
    bit<8>                              tmy_data_label_cnt;
    bit<32>                             ingress_pkt_cnt_val;
    bit<32>                             ingress_byte_cnt_val;
    bit<32>                             ingress_drop_cnt_val;
    bit<32>                             egress_pkt_cnt_val;
    bit<32>                             egress_byte_cnt_val;
    bit<32>                             egress_drop_cnt_val;
    tmy_inst_label_t                    tmy_inst_label;
    switch_id_t                         switch_id;
    bitmap_t                            bitmap;
    state_t                             state;
    ingress_port_t                      ingress_port;
    ingress_tstamp_t                    ingress_tstamp;
    ingress_pkt_cnt_t                   ingress_pkt_cnt;
    ingress_byte_cnt_t                  ingress_byte_cnt;
    ingress_drop_cnt_t                  ingress_drop_cnt;
    egress_port_t                       egress_port;
    egress_tstamp_t                     egress_tstamp;
    egress_pkt_cnt_t                    egress_pkt_cnt;
    egress_byte_cnt_t                   egress_byte_cnt;
    egress_drop_cnt_t                   egress_drop_cnt;
    enq_tstamp_t                        enq_tstamp;
    enq_qdepth_t                        enq_qdepth;
    deq_timedelta_t                     deq_timedelta;
    deq_qdepth_t                        deq_qdepth;
    pkt_len_t                           pkt_len;
    inst_type_t                         inst_type;
}

struct headers {
    ethernet_t                          ethernet;
    ipv4_t                              ipv4;
    tcp_t                               tcp;
    udp_t                               udp;
    fwd_header_t                        fwd_header;
    fwd_label_t[FWD_MAX_LABELS]         fwd_labels;
    tmy_inst_header_t                   tmy_inst_header;
    tmy_inst_label_t[TMY_MAX_LABELS]    tmy_inst_labels;
    tmy_data_header_t                   tmy_data_header;   

    switch_id_t                         switch_id;
    bitmap_t                            bitmap;
    state_t                             state;
    ingress_port_t                      ingress_port;
    ingress_tstamp_t                    ingress_tstamp;
    ingress_pkt_cnt_t                   ingress_pkt_cnt;
    ingress_byte_cnt_t                  ingress_byte_cnt;
    ingress_drop_cnt_t                  ingress_drop_cnt;
    egress_port_t                       egress_port;
    egress_tstamp_t                     egress_tstamp;
    egress_pkt_cnt_t                    egress_pkt_cnt;
    egress_byte_cnt_t                   egress_byte_cnt;
    egress_drop_cnt_t                   egress_drop_cnt;
    enq_tstamp_t                        enq_tstamp;
    enq_qdepth_t                        enq_qdepth;
    deq_timedelta_t                     deq_timedelta;
    deq_qdepth_t                        deq_qdepth;
    pkt_len_t                           pkt_len;
    inst_type_t                         inst_type;
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
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            PORT_FWD: parse_fwd_header;
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            PORT_FWD: parse_fwd_header;
            default : accept;
        }
    }

    state parse_fwd_header {
        packet.extract(hdr.fwd_header);
        meta.is_probe = 1;
        meta.fwd_label_cnt = hdr.fwd_header.label_cnt;
        transition select(meta.fwd_label_cnt) {
            0      : parse_tmy_inst_header;
            default: parse_fwd_label;
        }
    }

    state parse_fwd_label {
        packet.extract(hdr.fwd_labels.next);
        meta.fwd_label_cnt = meta.fwd_label_cnt - 1;
        transition select(meta.fwd_label_cnt) {
            0      : parse_tmy_inst_header;
            default: parse_fwd_label;
        }
    }

    state parse_tmy_inst_header {
        packet.extract(hdr.tmy_inst_header);
        meta.tmy_inst_label_cnt = hdr.tmy_inst_header.label_cnt;
        transition select(meta.tmy_inst_label_cnt) {
            0      : parse_tmy_data_header;
            default: parse_tmy_inst_label;
        }
    }

    state parse_tmy_inst_label {
        packet.extract(hdr.tmy_inst_labels.next);
        meta.tmy_inst_label_cnt = meta.tmy_inst_label_cnt - 1;
        transition select(meta.tmy_inst_label_cnt) {
            0      : parse_tmy_data_header;
            default: parse_tmy_inst_label;
        }
    }

    state parse_tmy_data_header {
        packet.extract(hdr.tmy_data_header);
        meta.tmy_data_label_cnt = hdr.tmy_data_header.label_cnt;
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

    register<bit<32>>(MAX_PORT_NUM) ingressPktCounter;
    register<bit<32>>(MAX_PORT_NUM) ingressByteCounter;
    register<bit<32>>(MAX_PORT_NUM) ingressDropCounter;

    action ingress_traffic_count() {
        ingressPktCounter.read(meta.ingress_pkt_cnt_val, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_pkt_cnt_val = meta.ingress_pkt_cnt_val + 1;
        ingressPktCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_pkt_cnt_val);

        ingressByteCounter.read(meta.ingress_byte_cnt_val, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_byte_cnt_val = meta.ingress_byte_cnt_val + standard_metadata.packet_length;
        ingressByteCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_byte_cnt_val);
    }

    action ingress_drop_count() {
        ingressDropCounter.read(meta.ingress_drop_cnt_val, (bit<32>)standard_metadata.ingress_port);
        meta.ingress_drop_cnt_val = meta.ingress_drop_cnt_val + (bit<32>)standard_metadata.drop;
        ingressDropCounter.write((bit<32>)standard_metadata.ingress_port, meta.ingress_drop_cnt_val);
    }

    action drop() {
        mark_to_drop();
    }
    
    action fwd_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.fwd_labels[0].outport;
        hdr.fwd_labels.pop_front(1);
        hdr.fwd_header.label_cnt = hdr.fwd_header.label_cnt - 1;
    }

    action fwd_header_invalid() {
        hdr.fwd_header.setInvalid();
    }

    action fwd_complete_tcp() {
        hdr.tcp.dstPort = PORT_TMY_DATA;
    }

    action fwd_complete_udp() {
        hdr.udp.dstPort = PORT_TMY_DATA;
    }

    action ipv4_forward(bit<9> port) {
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
                    fwd_header_invalid();
                    if (hdr.tcp.isValid()) {
                        fwd_complete_tcp();
                    }
                    if (hdr.udp.isValid()) {
                        fwd_complete_udp();
                    }
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
        egressPktCounter.read(meta.egress_pkt_cnt_val, (bit<32>)standard_metadata.egress_port);
        meta.egress_pkt_cnt_val = meta.egress_pkt_cnt_val + 1;
        egressPktCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_pkt_cnt_val);

        egressByteCounter.read(meta.egress_byte_cnt_val, (bit<32>)standard_metadata.egress_port);
        meta.egress_byte_cnt_val = meta.egress_byte_cnt_val + standard_metadata.packet_length;
        egressByteCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_byte_cnt_val);
    }

    action egress_drop_count() {
        egressDropCounter.read(meta.egress_drop_cnt_val, (bit<32>)standard_metadata.egress_port);
        meta.egress_drop_cnt_val = meta.egress_drop_cnt_val + (bit<32>)standard_metadata.drop;
        egressDropCounter.write((bit<32>)standard_metadata.egress_port, meta.egress_drop_cnt_val);
    }

    action pop_tmy_inst_label() {
        meta.tmy_inst_label = hdr.tmy_inst_labels[0];
        hdr.tmy_inst_labels.pop_front(1);
        hdr.tmy_inst_header.label_cnt = hdr.tmy_inst_header.label_cnt - 1;
    }

    action is_switch() {
        meta.is_switch = 1;
        pop_tmy_inst_label();
        hdr.tmy_data_header.label_cnt = hdr.tmy_data_header.label_cnt + 1;
    }

    action is_not_switch() {
        meta.is_switch = 0;
    }

    table check_switch_id {
        key = {
            hdr.tmy_inst_labels[0].switch_id: exact;
        }
        actions = {
            is_switch;
            is_not_switch;
        }
        size = 1;
        default_action = is_not_switch();
    }

    action add_switch_id_header() {
        meta.switch_id.setValid();
        meta.switch_id.switch_id = meta.tmy_inst_label.switch_id;
        hdr.switch_id = meta.switch_id;
    }

    action add_bitmap_header() {
        meta.bitmap.setValid();
        meta.bitmap.bit_state = meta.tmy_inst_label.bit_state;
        meta.bitmap.bit_ingress_port = meta.tmy_inst_label.bit_ingress_port;
        meta.bitmap.bit_ingress_tstamp = meta.tmy_inst_label.bit_ingress_tstamp;
        meta.bitmap.bit_ingress_pkt_cnt = meta.tmy_inst_label.bit_ingress_pkt_cnt;
        meta.bitmap.bit_ingress_byte_cnt = meta.tmy_inst_label.bit_ingress_byte_cnt;
        meta.bitmap.bit_ingress_drop_cnt = meta.tmy_inst_label.bit_ingress_drop_cnt;
        meta.bitmap.bit_egress_port = meta.tmy_inst_label.bit_egress_port;
        meta.bitmap.bit_egress_tstamp = meta.tmy_inst_label.bit_egress_tstamp;
        meta.bitmap.bit_egress_pkt_cnt = meta.tmy_inst_label.bit_egress_pkt_cnt;
        meta.bitmap.bit_egress_byte_cnt = meta.tmy_inst_label.bit_egress_byte_cnt;
        meta.bitmap.bit_egress_drop_cnt = meta.tmy_inst_label.bit_egress_drop_cnt;
        meta.bitmap.bit_enq_tstamp = meta.tmy_inst_label.bit_enq_tstamp;
        meta.bitmap.bit_enq_qdepth = meta.tmy_inst_label.bit_enq_qdepth;
        meta.bitmap.bit_deq_timedelta = meta.tmy_inst_label.bit_deq_timedelta;
        meta.bitmap.bit_deq_qdepth = meta.tmy_inst_label.bit_deq_qdepth;
        meta.bitmap.bit_pkt_len = meta.tmy_inst_label.bit_pkt_len;
        meta.bitmap.bit_inst_type = meta.tmy_inst_label.bit_inst_type;
        meta.bitmap.bit_reserved = meta.tmy_inst_label.bit_reserved;
        hdr.bitmap = meta.bitmap;
    }

    action add_state_header(bit<8> state) {
        meta.state.setValid();
        meta.state.state = state;
        hdr.state = meta.state;
    }

    table check_bit_state {
        key = {
            meta.tmy_inst_label.bit_state: exact;
        }
        actions = {
            add_state_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_ingress_port_header() {
        meta.ingress_port.setValid();
        meta.ingress_port.ingress_port = (bit<8>)standard_metadata.ingress_port;
        hdr.ingress_port = meta.ingress_port;
    }

    table check_bit_ingress_port {
        key = {
            meta.tmy_inst_label.bit_ingress_port: exact;
        }
        actions = {
            add_ingress_port_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_ingress_tstamp_header() {
        meta.ingress_tstamp.setValid();
        meta.ingress_tstamp.ingress_tstamp = standard_metadata.ingress_global_timestamp;
        hdr.ingress_tstamp = meta.ingress_tstamp;
    }

    table check_bit_ingress_tstamp {
        key = {
            meta.tmy_inst_label.bit_ingress_tstamp: exact;
        }
        actions = {
            add_ingress_tstamp_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_ingress_pkt_cnt_header() {
        meta.ingress_pkt_cnt.setValid();
        meta.ingress_pkt_cnt.ingress_pkt_cnt = meta.ingress_pkt_cnt_val;
        hdr.ingress_pkt_cnt = meta.ingress_pkt_cnt;
    }

    table check_bit_ingress_pkt_cnt {
        key = {
            meta.tmy_inst_label.bit_ingress_pkt_cnt: exact;
        }
        actions = {
            add_ingress_pkt_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_ingress_byte_cnt_header() {
        meta.ingress_byte_cnt.setValid();
        meta.ingress_byte_cnt.ingress_byte_cnt = meta.ingress_byte_cnt_val;
        hdr.ingress_byte_cnt = meta.ingress_byte_cnt;
    }

    table check_bit_ingress_byte_cnt {
        key = {
            meta.tmy_inst_label.bit_ingress_byte_cnt: exact;
        }
        actions = {
            add_ingress_byte_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_ingress_drop_cnt_header() {
        meta.ingress_drop_cnt.setValid();
        meta.ingress_drop_cnt.ingress_drop_cnt = meta.ingress_drop_cnt_val;
        hdr.ingress_drop_cnt = meta.ingress_drop_cnt;
    }

    table check_bit_ingress_drop_cnt {
        key = {
            meta.tmy_inst_label.bit_ingress_drop_cnt: exact;
        }
        actions = {
            add_ingress_drop_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_egress_port_header() {
        meta.egress_port.setValid();
        meta.egress_port.egress_port = (bit<8>)standard_metadata.egress_port;
        hdr.egress_port = meta.egress_port;
    }

    table check_bit_egress_port {
        key = {
            meta.tmy_inst_label.bit_egress_port: exact;
        }
        actions = {
            add_egress_port_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_egress_tstamp_header() {
        meta.egress_tstamp.setValid();
        meta.egress_tstamp.egress_tstamp = standard_metadata.egress_global_timestamp;
        hdr.egress_tstamp = meta.egress_tstamp;
    }

    table check_bit_egress_tstamp {
        key = {
            meta.tmy_inst_label.bit_egress_tstamp: exact;
        }
        actions = {
            add_egress_tstamp_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_egress_pkt_cnt_header() {
        meta.egress_pkt_cnt.setValid();
        meta.egress_pkt_cnt.egress_pkt_cnt = meta.egress_pkt_cnt_val;
        hdr.egress_pkt_cnt = meta.egress_pkt_cnt;
    }

    table check_bit_egress_pkt_cnt {
        key = {
            meta.tmy_inst_label.bit_egress_pkt_cnt: exact;
        }
        actions = {
            add_egress_pkt_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_egress_byte_cnt_header() {
        meta.egress_byte_cnt.setValid();
        meta.egress_byte_cnt.egress_byte_cnt = meta.egress_byte_cnt_val;
        hdr.egress_byte_cnt = meta.egress_byte_cnt;
    }

    table check_bit_egress_byte_cnt {
        key = {
            meta.tmy_inst_label.bit_egress_byte_cnt: exact;
        }
        actions = {
            add_egress_byte_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_egress_drop_cnt_header() {
        meta.egress_drop_cnt.setValid();
        meta.egress_drop_cnt.egress_drop_cnt = meta.egress_drop_cnt_val;
        hdr.egress_drop_cnt = meta.egress_drop_cnt;
    }

    table check_bit_egress_drop_cnt {
        key = {
            meta.tmy_inst_label.bit_egress_drop_cnt: exact;
        }
        actions = {
            add_egress_drop_cnt_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_enq_tstamp_header() {
        meta.enq_tstamp.setValid();
        meta.enq_tstamp.enq_tstamp = standard_metadata.enq_timestamp;
        hdr.enq_tstamp = meta.enq_tstamp;
    }

    table check_bit_enq_tstamp {
        key = {
            meta.tmy_inst_label.bit_enq_tstamp: exact;
        }
        actions = {
            add_enq_tstamp_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_enq_qdepth_header() {
        meta.enq_qdepth.setValid();
        meta.enq_qdepth.enq_qdepth = standard_metadata.enq_qdepth;
        hdr.enq_qdepth = meta.enq_qdepth;
    }

    table check_bit_enq_qdepth {
        key = {
            meta.tmy_inst_label.bit_enq_qdepth: exact;
        }
        actions = {
            add_enq_qdepth_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_deq_timedelta_header() {
        meta.deq_timedelta.setValid();
        meta.deq_timedelta.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.deq_timedelta = meta.deq_timedelta;
    }

    table check_bit_deq_timedelta {
        key = {
            meta.tmy_inst_label.bit_deq_timedelta: exact;
        }
        actions = {
            add_deq_timedelta_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_deq_qdepth_header() {
        meta.deq_qdepth.setValid();
        meta.deq_qdepth.deq_qdepth = standard_metadata.deq_qdepth;
        hdr.deq_qdepth = meta.deq_qdepth;
    }

    table check_bit_deq_qdepth {
        key = {
            meta.tmy_inst_label.bit_deq_qdepth: exact;
        }
        actions = {
            add_deq_qdepth_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_pkt_len_header() {
        meta.pkt_len.setValid();
        meta.pkt_len.pkt_len = standard_metadata.packet_length;
        hdr.pkt_len = meta.pkt_len;
    }

    table check_bit_pkt_len {
        key = {
            meta.tmy_inst_label.bit_pkt_len: exact;
        }
        actions = {
            add_pkt_len_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    action add_inst_type_header() {
        meta.inst_type.setValid();
        meta.inst_type.inst_type = standard_metadata.instance_type;
        hdr.inst_type = meta.inst_type;
    }

    table check_bit_inst_type {
        key = {
            meta.tmy_inst_label.bit_inst_type: exact;
        }
        actions = {
            add_inst_type_header;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    apply {
        egress_traffic_count();
        egress_drop_count();

        if (meta.is_probe == 1) {
            check_switch_id.apply();
            if (meta.is_switch == 1) {
                add_switch_id_header();
                add_bitmap_header();
                check_bit_state.apply();
                check_bit_ingress_port.apply();
                check_bit_ingress_tstamp.apply();
                check_bit_ingress_pkt_cnt.apply();
                check_bit_ingress_byte_cnt.apply();
                check_bit_ingress_drop_cnt.apply();
                check_bit_egress_port.apply();
                check_bit_egress_tstamp.apply();
                check_bit_egress_pkt_cnt.apply();
                check_bit_egress_byte_cnt.apply();
                check_bit_egress_drop_cnt.apply();
                check_bit_enq_tstamp.apply();
                check_bit_enq_qdepth.apply();
                check_bit_deq_timedelta.apply();
                check_bit_deq_qdepth.apply();
                check_bit_pkt_len.apply();
                check_bit_inst_type.apply();
            }
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
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.fwd_header);
        packet.emit(hdr.fwd_labels);
        packet.emit(hdr.tmy_inst_header);
        packet.emit(hdr.tmy_inst_labels);
        packet.emit(hdr.tmy_data_header);
        packet.emit(hdr.switch_id);
        packet.emit(hdr.bitmap);
        packet.emit(hdr.state);
        packet.emit(hdr.ingress_port);
        packet.emit(hdr.ingress_tstamp);
        packet.emit(hdr.ingress_pkt_cnt);
        packet.emit(hdr.ingress_byte_cnt);
        packet.emit(hdr.ingress_drop_cnt);
        packet.emit(hdr.egress_port);
        packet.emit(hdr.egress_tstamp);
        packet.emit(hdr.egress_pkt_cnt);
        packet.emit(hdr.egress_byte_cnt);
        packet.emit(hdr.egress_drop_cnt);
        packet.emit(hdr.enq_tstamp);
        packet.emit(hdr.enq_qdepth);
        packet.emit(hdr.deq_timedelta);
        packet.emit(hdr.deq_qdepth);
        packet.emit(hdr.pkt_len);
        packet.emit(hdr.inst_type);
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
