/* dpsi.p4 - DPSI: P4-based Stateful Detection for DDoS and ARP Spoofing */

#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP = 0x0806;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    arp_t arp;
}

struct metadata { }

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control IngressImpl(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
    // Register to track per-source IP traffic counts
    register<bit<32>>(1024) src_ip_counter;

    action drop() {
        mark_to_drop();
    }

    action forward(bit<9> port) {
        smeta.egress_spec = port;
    }

    table ddos_table {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            drop;
            forward;
            NoAction;
        }
        size = 1024;
    }

    apply {
        if (hdr.ethernet.etherType == ETHERTYPE_IPV4) {
            ddos_table.apply();
        } else if (hdr.ethernet.etherType == ETHERTYPE_ARP) {
            if (hdr.arp.sha == 0 || hdr.arp.spa == 0) {
                drop();
            }
        }
    }
}

control EgressImpl(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) { apply { } }

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ethernet.etherType == ETHERTYPE_IPV4) {
            packet.emit(hdr.ipv4);
        } else if (hdr.ethernet.etherType == ETHERTYPE_ARP) {
            packet.emit(hdr.arp);
        }
    }
}

V1Switch(ParserImpl(), IngressImpl(), EgressImpl(), DeparserImpl()) main;