// ethernet.etherType
#define TYPE_IPv4 0x0800
// ipv4.protocol
#define TYPE_TCP 0x0006
#define TYPE_UDP 0x0011
// tcp or udp .dstPort
#define PORT_FWD 0xffff
#define PORT_TMY_DATA 0xfffe

#define PROTO_TMY_INST 0xff
#define PROTO_TMY_DATA 0xfe

#define MAX_PORT_NUM 256

#define FWD_MAX_LABELS  100
#define TMY_MAX_LABELS  100

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header_type ethernet_t {
    fields {
        dstAddr: 48;
        srcAddr: 48;
        etherType: 16;
    }
}
header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version: 4;
        ihl: 4;
        diffserv: 8;
        totalLen: 16;
        identification: 16;
        flags: 3;
        fragOffset: 13;
        ttl: 8;
        protocol: 8;
        hdrChecksum: 16;
        srcAddr: 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;

header_type tcp_t {
    fields {
        srcPort: 16;
        dstPort: 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 3;
        ecn: 3;
        ctrl: 6;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}
header tcp_t tcp;

header_type udp_t {
    fields {
        srcPort: 16;
        dstPort: 16;
        len: 16;
        checksum: 16;
    }
}
header udp_t udp;

header_type fwd_header_t {
    fields {
        proto: 8;
    }
}
header fwd_header_t fwd_header;

header_type fwd_label_t {
    fields {
        outport: 8;
        tos: 8;
    }
}
header fwd_label_t fwd_labels[FWD_MAX_LABELS];

header_type tmy_inst_label_t {
    fields {
        switch_id: 16;          // switch_id
        // metadata bitmap
        bit_state: 1;
        bit_ingress_port: 1;
        bit_ingress_tstamp: 1;
        bit_ingress_pkt_cnt: 1;
        bit_ingress_byte_cnt: 1;
        bit_ingress_drop_cnt: 1;
        bit_egress_port: 1;
        bit_egress_tstamp: 1;
        bit_egress_pkt_cnt: 1;
        bit_egress_byte_cnt: 1;
        bit_egress_drop_cnt: 1;
        bit_enq_tstamp: 1;
        bit_enq_qdepth: 1;
        bit_deq_timedelta: 1;
        bit_deq_qdepth: 1;
        bit_pkt_len: 1;
        bit_inst_type: 1;
        bit_reserved: 7;
        tos: 8;
    }
}
header tmy_inst_label_t tmy_inst_labels[TMY_MAX_LABELS];

header_type switch_id_t {
    fields {
        switch_id: 16;          // switch_id
    }
}
header switch_id_t switch_id;

header_type bitmap_t {
    fields {
        // metadata bitmap
        bit_state: 1;
        bit_ingress_port: 1;
        bit_ingress_tstamp: 1;
        bit_ingress_pkt_cnt: 1;
        bit_ingress_byte_cnt: 1;
        bit_ingress_drop_cnt: 1;
        bit_egress_port: 1;
        bit_egress_tstamp: 1;
        bit_egress_pkt_cnt: 1;
        bit_egress_byte_cnt: 1;
        bit_egress_drop_cnt: 1;
        bit_enq_tstamp: 1;
        bit_enq_qdepth: 1;
        bit_deq_timedelta: 1;
        bit_deq_qdepth: 1;
        bit_pkt_len: 1;
        bit_inst_type: 1;
        bit_reserved: 7;
    }
}
header bitmap_t bitmap;

// switch metadata
header_type state_t {
    fields {
        state: 8;              // control_plane_state_version
    }
}
header state_t state;

// ingress metadata
header_type ingress_port_t {
    fields {
        ingress_port: 8;        // ingress_port_id
    }
}
header ingress_port_t ingress_port;

header_type ingress_tstamp_t {
    fields {
        ingress_tstamp: 48;     // ingress_timestamp
    }
}
header ingress_tstamp_t ingress_tstamp;

header_type ingress_pkt_cnt_t {
    fields {
        ingress_pkt_cnt: 32;    // ingress_port_RX_pkt_count
    }
}
header ingress_pkt_cnt_t ingress_pkt_cnt;

header_type ingress_byte_cnt_t {
    fields {
        ingress_byte_cnt: 32;   // ingress_port_RX_byte_count
    }
}
header ingress_byte_cnt_t ingress_byte_cnt;

header_type ingress_drop_cnt_t {
    fields {
        ingress_drop_cnt: 32;   // ingress_port_RX_drop_count
    }
}
header ingress_drop_cnt_t ingress_drop_cnt;

// egress metadata
header_type egress_port_t {
    fields {
        egress_port: 8;        // egress_port_id
    }
}
header egress_port_t egress_port;

header_type egress_tstamp_t {
    fields {
        egress_tstamp: 48;     // egress_timestamp
    }
}
header egress_tstamp_t egress_tstamp;

header_type egress_pkt_cnt_t {
    fields {
        egress_pkt_cnt: 32;    // egress_port_TX_pkt_count
    }
}
header egress_pkt_cnt_t egress_pkt_cnt;

header_type egress_byte_cnt_t {
    fields {
        egress_byte_cnt: 32;   // egress_port_TX_byte_count
    }
}
header egress_byte_cnt_t egress_byte_cnt;

header_type egress_drop_cnt_t {
    fields {
        egress_drop_cnt: 32;   // egress_port_TX_drop_count
    }
}
header egress_drop_cnt_t egress_drop_cnt;

// buffer metadata
header_type enq_tstamp_t {
    fields {
        enq_tstamp: 32;         // enq_timestamp
    }
}
header enq_tstamp_t enq_tstamp;

header_type enq_qdepth_t {
    fields {
        enq_qdepth: 16;         // enq_qdepth
    }
}
header enq_qdepth_t enq_qdepth;

header_type deq_timedelta_t {
    fields {
        deq_timedelta: 32;      // deq_timedelta
    }
}
header deq_timedelta_t deq_timedelta;

header_type deq_qdepth_t {
    fields {
        deq_qdepth: 16;        // deq_qdepth
    }
}
header deq_qdepth_t deq_qdepth;

// packet metadata
header_type pkt_len_t {
    fields {
        pkt_len: 32;           // packet_length
    }
}
header pkt_len_t pkt_len;

header_type inst_type_t {
    fields {
        inst_type: 32;         // instance_type
    }
}
header inst_type_t inst_type;

header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 48;
        egress_global_timestamp : 48;
        lf_field_list : 8;
        mcast_grp : 16;
        egress_rid : 16;
        resubmit_flag : 8;
        recirculate_flag : 8;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;

header_type queueing_metadata_t {
    fields {
        enq_timestamp : 48;
        enq_qdepth : 16;
        deq_timedelta : 32;
        deq_qdepth : 16;
        qid : 8;
    }
}
metadata queueing_metadata_t queueing_metadata;

header_type metadata_t {
    fields {
        drop: 1;
        is_probe: 1;    
        is_switch: 1;   
        tmy_proto: 8;     
        fwd_label_cnt: 8;
        tmy_inst_label_cnt: 8;
        switch_id: 16;          // switch_id
        // metadata bitmap
        bit_state: 1;
        bit_ingress_port: 1;
        bit_ingress_tstamp: 1;
        bit_ingress_pkt_cnt: 1;
        bit_ingress_byte_cnt: 1;
        bit_ingress_drop_cnt: 1;
        bit_egress_port: 1;
        bit_egress_tstamp: 1;
        bit_egress_pkt_cnt: 1;
        bit_egress_byte_cnt: 1;
        bit_egress_drop_cnt: 1;
        bit_enq_tstamp: 1;
        bit_enq_qdepth: 1;
        bit_deq_timedelta: 1;
        bit_deq_qdepth: 1;
        bit_pkt_len: 1;
        bit_inst_type: 1;
        bit_reserved: 7;
        tos: 8;
        tmy_data_label_cnt: 8;
        ingress_pkt_cnt_val: 32;
        ingress_byte_cnt_val: 32;
        ingress_drop_cnt_val: 32;
        egress_pkt_cnt_val: 32;
        egress_byte_cnt_val: 32;
        egress_drop_cnt_val: 32;
    }
}
metadata metadata_t meta;


field_list ipv4_checksum_fields {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum_calc {
    input {
        ipv4_checksum_fields;
    }
    algorithm: crc16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum_calc if (valid(ipv4));
    update ipv4_checksum_calc if (valid(ipv4));
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

    
parser start {
    set_metadata(meta.is_probe, 0);
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(ethernet.etherType) {
        TYPE_IPv4: parse_ipv4;
        default  : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        TYPE_TCP: parse_tcp;
        TYPE_UDP: parse_udp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return select(tcp.dstPort) {
        PORT_FWD: parse_fwd_header;
        default : ingress;
    }
}

parser parse_udp {
    extract(udp);
    return select(udp.dstPort) {
        PORT_FWD: parse_fwd_header;
        default : ingress;
    }
}

parser parse_fwd_header {
    extract(fwd_header);
    set_metadata(meta.is_probe, 1);
    set_metadata(meta.tmy_proto, fwd_header.proto);
    return parse_fwd_label;
}

parser parse_fwd_label {
    extract(fwd_labels[next]);
    return select(latest.tos, meta.tmy_proto) {
        1, PROTO_TMY_INST : parse_tmy_inst_label;
        1, PROTO_TMY_DATA : ingress;
        default: parse_fwd_label;
    }
}


parser parse_tmy_inst_label {
    extract(tmy_inst_labels[next]);
    return select(latest.tos) {
        0      : parse_tmy_inst_label;
        default: ingress;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register ingressPktCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

register ingressByteCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

register ingressDropCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

action pass() {
}

action mark_drop() {
    modify_field(meta.drop, 1);
    drop();
}

table mark_drop {
    actions {
        mark_drop;
    }
}

action ingress_traffic_count() {
    register_read(meta.ingress_pkt_cnt_val, ingressPktCounter, standard_metadata.ingress_port);
    add_to_field(meta.ingress_pkt_cnt_val, 1);
    register_write(ingressPktCounter, standard_metadata.ingress_port, meta.ingress_pkt_cnt_val);

    register_read(meta.ingress_byte_cnt_val, ingressByteCounter, standard_metadata.ingress_port);
    add_to_field(meta.ingress_byte_cnt_val, standard_metadata.packet_length);
    register_write(ingressByteCounter, standard_metadata.ingress_port, meta.ingress_byte_cnt_val);
}

table ingress_traffic_count {
    actions {
        ingress_traffic_count;
    }
}

action ingress_drop_count() {
    register_read(meta.ingress_drop_cnt_val, ingressDropCounter, standard_metadata.ingress_port);
    add_to_field(meta.ingress_drop_cnt_val, meta.drop);
    register_write(ingressDropCounter, standard_metadata.ingress_port, meta.ingress_drop_cnt_val);
}

table ingress_drop_count {
    actions {
        ingress_drop_count;
    }
}

action fwd_nhop() {
    modify_field(standard_metadata.egress_spec, fwd_labels[0].outport);
    pop(fwd_labels, 1);
}

table fwd_nhop {
    actions {
        fwd_nhop;
    }
}

action fwd_header_invalid() {
    remove_header(fwd_header);
}

table fwd_header_invalid {
    actions {
        fwd_header_invalid;
    }
}
action fwd_complete_tcp() {
    modify_field(tcp.dstPort, PORT_TMY_DATA);
}

table fwd_complete_tcp {
    actions {
        fwd_complete_tcp;
    }
}

action fwd_complete_udp() {
    modify_field(udp.dstPort, PORT_TMY_DATA);
}

table fwd_complete_udp {
    actions {
        fwd_complete_udp;
    }
}

action ipv4_forward(port) {
    modify_field(standard_metadata.egress_spec, port);
    subtract_from_field(ipv4.ttl, 1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr: lpm;
    }
    actions {
        ipv4_forward;
        mark_drop;
        pass;
    }
    size: 1024;
}

action test() {
    modify_field(ethernet.dstAddr, 1);
}

table test {
    actions {
        test;
    }
}

control ingress {
    apply(ingress_traffic_count);

    if (meta.is_probe == 0) {
        if (ethernet.etherType == TYPE_IPv4) {
            if (ipv4.ttl == 0) {
                apply(mark_drop);
            }
            else {
                apply(ipv4_lpm);
            }
        }
    }
    else {
        if (valid(fwd_labels[0])) {
            if (fwd_labels[0].tos == 1) {
                apply(fwd_header_invalid);
                if (valid(tcp)) {
                    apply(fwd_complete_tcp);
                }
                if (valid(udp)) {
                    apply(fwd_complete_udp);
                }
            }
            apply(fwd_nhop);
        }
        else {
            apply(mark_drop);
        }
    }

    apply(ingress_drop_count);
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register egressPktCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

register egressByteCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

register egressDropCounter {
    width: 32;
    instance_count: MAX_PORT_NUM;
}

action egress_traffic_count() {
    register_read(meta.egress_pkt_cnt_val, egressPktCounter, standard_metadata.egress_port);
    add_to_field(meta.egress_pkt_cnt_val, 1);
    register_write(egressPktCounter, standard_metadata.egress_port, meta.egress_pkt_cnt_val);

    register_read(meta.egress_byte_cnt_val, egressByteCounter, standard_metadata.egress_port);
    add_to_field(meta.egress_byte_cnt_val, standard_metadata.packet_length);
    register_write(egressByteCounter, standard_metadata.egress_port, meta.egress_byte_cnt_val);
}

table egress_traffic_count {
    actions {
        egress_traffic_count;
    }
}

action egress_drop_count() {
    register_read(meta.egress_drop_cnt_val, egressDropCounter, standard_metadata.egress_port);
    add_to_field(meta.egress_drop_cnt_val, meta.drop);
    register_write(egressDropCounter, standard_metadata.egress_port, meta.egress_drop_cnt_val);
}

table egress_drop_count {
    actions {
        egress_drop_count;
    }
}

action pop_tmy_inst_label() {
    modify_field(meta.switch_id, tmy_inst_labels[0].switch_id);
    modify_field(meta.bit_state, tmy_inst_labels[0].bit_state);
    modify_field(meta.bit_ingress_port, tmy_inst_labels[0].bit_ingress_port);
    modify_field(meta.bit_ingress_tstamp, tmy_inst_labels[0].bit_ingress_tstamp);
    modify_field(meta.bit_ingress_pkt_cnt, tmy_inst_labels[0].bit_ingress_pkt_cnt);
    modify_field(meta.bit_ingress_byte_cnt, tmy_inst_labels[0].bit_ingress_byte_cnt);
    modify_field(meta.bit_ingress_drop_cnt, tmy_inst_labels[0].bit_ingress_drop_cnt);
    modify_field(meta.bit_egress_port, tmy_inst_labels[0].bit_egress_port);
    modify_field(meta.bit_egress_tstamp, tmy_inst_labels[0].bit_egress_tstamp);
    modify_field(meta.bit_egress_pkt_cnt, tmy_inst_labels[0].bit_egress_pkt_cnt);
    modify_field(meta.bit_egress_byte_cnt, tmy_inst_labels[0].bit_egress_byte_cnt);
    modify_field(meta.bit_egress_drop_cnt, tmy_inst_labels[0].bit_egress_drop_cnt);
    modify_field(meta.bit_enq_tstamp, tmy_inst_labels[0].bit_enq_tstamp);
    modify_field(meta.bit_enq_qdepth, tmy_inst_labels[0].bit_enq_qdepth);
    modify_field(meta.bit_deq_timedelta, tmy_inst_labels[0].bit_deq_timedelta);
    modify_field(meta.bit_deq_qdepth, tmy_inst_labels[0].bit_deq_qdepth);
    modify_field(meta.bit_pkt_len, tmy_inst_labels[0].bit_pkt_len);
    modify_field(meta.bit_inst_type, tmy_inst_labels[0].bit_inst_type);
    modify_field(meta.bit_reserved, tmy_inst_labels[0].bit_reserved);
    pop(tmy_inst_labels, 1);
}

action is_switch() {
    modify_field(meta.is_switch, 1);
    pop_tmy_inst_label();
}

action is_not_switch() {
    modify_field(meta.is_switch, 0);
}

table check_switch_id {
    reads {
        tmy_inst_labels[0].switch_id: exact;
    }
    actions {
        is_switch;
        is_not_switch;
    }
    size: 1;
}

action add_switch_id_header() {
    add_header(switch_id);
    modify_field(switch_id.switch_id, meta.switch_id);
}

table add_switch_id_header {
    actions {
        add_switch_id_header;
    }
}

action add_bitmap_header() {
    add_header(bitmap);
    modify_field(bitmap.bit_state, meta.bit_state);
    modify_field(bitmap.bit_ingress_port, meta.bit_ingress_port);
    modify_field(bitmap.bit_ingress_tstamp, meta.bit_ingress_tstamp);
    modify_field(bitmap.bit_ingress_pkt_cnt, meta.bit_ingress_pkt_cnt);
    modify_field(bitmap.bit_ingress_byte_cnt, meta.bit_ingress_byte_cnt);
    modify_field(bitmap.bit_ingress_drop_cnt, meta.bit_ingress_drop_cnt);
    modify_field(bitmap.bit_egress_port, meta.bit_egress_port);
    modify_field(bitmap.bit_egress_tstamp, meta.bit_egress_tstamp);
    modify_field(bitmap.bit_egress_pkt_cnt, meta.bit_egress_pkt_cnt);
    modify_field(bitmap.bit_egress_byte_cnt, meta.bit_egress_byte_cnt);
    modify_field(bitmap.bit_egress_drop_cnt, meta.bit_egress_drop_cnt);
    modify_field(bitmap.bit_enq_tstamp, meta.bit_enq_tstamp);
    modify_field(bitmap.bit_enq_qdepth, meta.bit_enq_qdepth);
    modify_field(bitmap.bit_deq_timedelta, meta.bit_deq_timedelta);
    modify_field(bitmap.bit_deq_qdepth, meta.bit_deq_qdepth);
    modify_field(bitmap.bit_pkt_len, meta.bit_pkt_len);
    modify_field(bitmap.bit_inst_type, meta.bit_inst_type);
    modify_field(bitmap.bit_reserved, meta.bit_reserved);  
}

table add_bitmap_header {
    actions {
        add_bitmap_header;
    }
}

action add_state_header(state_val) {
    add_header(state);
    modify_field(state.state, state_val);
}

table check_bit_state {
    reads {
        meta.bit_state: exact;
    }
    actions {
        add_state_header;
        pass;
    }
    size: 1;
}

action add_ingress_port_header() {
    add_header(ingress_port);
    modify_field(ingress_port.ingress_port, standard_metadata.ingress_port);
}

table check_bit_ingress_port {
    reads {
        meta.bit_ingress_port: exact;
    }
    actions {
        add_ingress_port_header;
        pass;
    }
    size: 1;
}

action add_ingress_tstamp_header() {
    add_header(ingress_tstamp);
    modify_field(ingress_tstamp.ingress_tstamp, intrinsic_metadata.ingress_global_timestamp);
}

table check_bit_ingress_tstamp {
    reads {
        meta.bit_ingress_tstamp: exact;
    }
    actions {
        add_ingress_tstamp_header;
        pass;
    }
    size: 1;
}

action add_ingress_pkt_cnt_header() {
    add_header(ingress_pkt_cnt);
    modify_field(ingress_pkt_cnt.ingress_pkt_cnt, meta.ingress_pkt_cnt_val);
}

table check_bit_ingress_pkt_cnt {
    reads {
        meta.bit_ingress_pkt_cnt: exact;
    }
    actions {
        add_ingress_pkt_cnt_header;
        pass;
    }
    size: 1;
}

action add_ingress_byte_cnt_header() {
    add_header(ingress_byte_cnt);
    modify_field(ingress_byte_cnt.ingress_byte_cnt, meta.ingress_byte_cnt_val);
}

table check_bit_ingress_byte_cnt {
    reads {
        meta.bit_ingress_byte_cnt: exact;
    }
    actions {
        add_ingress_byte_cnt_header;
        pass;
    }
    size: 1;
}

action add_ingress_drop_cnt_header() {
    add_header(ingress_drop_cnt);
    modify_field(ingress_drop_cnt.ingress_drop_cnt, meta.ingress_drop_cnt_val);
}

table check_bit_ingress_drop_cnt {
    reads {
        meta.bit_ingress_drop_cnt: exact;
    }
    actions {
        add_ingress_drop_cnt_header;
        pass;
    }
    size: 1;
}

action add_egress_port_header() {
    add_header(egress_port);
    modify_field(egress_port.egress_port, standard_metadata.egress_port);
}

table check_bit_egress_port {
    reads {
        meta.bit_egress_port: exact;
    }
    actions {
        add_egress_port_header;
        pass;
    }
    size: 1;
}

action add_egress_tstamp_header() {
    add_header(egress_tstamp);
    modify_field(egress_tstamp.egress_tstamp, intrinsic_metadata.egress_global_timestamp);
}

table check_bit_egress_tstamp {
    reads {
        meta.bit_egress_tstamp: exact;
    }
    actions {
        add_egress_tstamp_header;
        pass;
    }
    size: 1;
}

action add_egress_pkt_cnt_header() {
    add_header(egress_pkt_cnt);
    modify_field(egress_pkt_cnt.egress_pkt_cnt, meta.egress_pkt_cnt_val);
}

table check_bit_egress_pkt_cnt {
    reads {
        meta.bit_egress_pkt_cnt: exact;
    }
    actions {
        add_egress_pkt_cnt_header;
        pass;
    }
    size: 1;
}

action add_egress_byte_cnt_header() {
    add_header(egress_byte_cnt);
    modify_field(egress_byte_cnt.egress_byte_cnt, meta.egress_byte_cnt_val);
}

table check_bit_egress_byte_cnt {
    reads {
        meta.bit_egress_byte_cnt: exact;
    }
    actions {
        add_egress_byte_cnt_header;
        pass;
    }
    size: 1;
}

action add_egress_drop_cnt_header() {
    add_header(egress_drop_cnt);
    modify_field(egress_drop_cnt.egress_drop_cnt, meta.egress_drop_cnt_val);
}

table check_bit_egress_drop_cnt {
    reads {
        meta.bit_egress_drop_cnt: exact;
    }
    actions {
        add_egress_drop_cnt_header;
        pass;
    }
    size: 1;
}

action add_enq_tstamp_header() {
    add_header(enq_tstamp);
    modify_field(enq_tstamp.enq_tstamp, queueing_metadata.enq_timestamp);
}

table check_bit_enq_tstamp {
    reads {
        meta.bit_enq_tstamp: exact;
    }
    actions {
        add_enq_tstamp_header;
        pass;
    }
    size: 1;
}

action add_enq_qdepth_header() {
    add_header(enq_qdepth);
    modify_field(enq_qdepth.enq_qdepth, queueing_metadata.enq_qdepth);
}

table check_bit_enq_qdepth {
    reads {
        meta.bit_enq_qdepth: exact;
    }
    actions {
        add_enq_qdepth_header;
        pass;
    }
    size: 1;
}

action add_deq_timedelta_header() {
    add_header(deq_timedelta);
    modify_field(deq_timedelta.deq_timedelta, queueing_metadata.deq_timedelta);
}

table check_bit_deq_timedelta {
    reads {
        meta.bit_deq_timedelta: exact;
    }
    actions {
        add_deq_timedelta_header;
        pass;
    }
    size: 1;
}

action add_deq_qdepth_header() {
    add_header(deq_qdepth);
    modify_field(deq_qdepth.deq_qdepth, queueing_metadata.deq_qdepth);
}

table check_bit_deq_qdepth {
    reads {
        meta.bit_deq_qdepth: exact;
    }
    actions {
        add_deq_qdepth_header;
        pass;
    }
    size: 1;
}

action add_pkt_len_header() {
    add_header(pkt_len);
    modify_field(pkt_len.pkt_len, standard_metadata.packet_length);
}

table check_bit_pkt_len {
    reads {
        meta.bit_pkt_len: exact;
    }
    actions {
        add_pkt_len_header;
        pass;
    }
    size: 1;
}

action add_inst_type_header() {
    add_header(inst_type);
    modify_field(inst_type.inst_type, standard_metadata.instance_type);
}

table check_bit_inst_type {
    reads {
        meta.bit_inst_type: exact;
    }
    actions {
        add_inst_type_header;
        pass;
    }
    size: 1;
}

action tmy_inst_complete() {
    modify_field(fwd_header.proto, PROTO_TMY_DATA);
}

table tmy_inst_complete {
    actions {
        tmy_inst_complete;
    }
}

control egress {
    apply(egress_traffic_count);
    apply(egress_drop_count);

    if (valid(tmy_inst_labels[0])) {
        apply(check_switch_id);
        if (meta.is_switch == 1) {
            apply(test);
            /*apply(add_switch_id_header);
            apply(add_bitmap_header);
            apply(check_bit_state);
            apply(check_bit_ingress_port);
            apply(check_bit_ingress_tstamp);
            apply(check_bit_ingress_pkt_cnt);
            apply(check_bit_ingress_byte_cnt);
            apply(check_bit_ingress_drop_cnt);
            apply(check_bit_egress_port);
            apply(check_bit_egress_tstamp);
            apply(check_bit_egress_pkt_cnt);
            apply(check_bit_egress_byte_cnt);
            apply(check_bit_egress_drop_cnt);
            apply(check_bit_enq_tstamp);
            apply(check_bit_enq_qdepth);
            apply(check_bit_deq_timedelta);
            apply(check_bit_deq_qdepth);
            apply(check_bit_pkt_len);
            apply(check_bit_inst_type);
            if (valid(tmy_inst_labels[0])) {
            } 
            else {
                apply(tmy_inst_complete);
            }*/
        }
    }
}
