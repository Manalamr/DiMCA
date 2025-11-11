
/* DMCA DPSI Module: dpsi.p4 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;

// Headers
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

// Parsed headers struct
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
}

// Metadata
struct metadata {
    bit<1> arp_conflict;
}

// Parser
parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

// Match-Action tables

register<bit<48>>(1024) ip_mac_bindings;

action detect_arp_conflict(bit<32> spa, bit<48> sha) {
    bit<48> stored_mac;
    ip_mac_bindings.read(stored_mac, spa);
    if (stored_mac != 0 && stored_mac != sha) {
        meta.arp_conflict = 1;
    } else {
        ip_mac_bindings.write(spa, sha);
    }
}

table arp_conflict_check {
    actions = {
        detect_arp_conflict;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
}

// Digest
struct Digest_t {
    bit<32> spa;
    bit<48> sha;
    bit<1>  conflict;
}

action send_digest(bit<32> spa, bit<48> sha) {
    Digest_t d;
    d.spa = spa;
    d.sha = sha;
    d.conflict = 1;
    send_digest(d);
}

table report_digest {
    actions = {
        send_digest;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
}

// Control
control MyIngress(inout headers hdr, inout metadata meta,
                  inout standard_metadata_t stdmeta) {
    apply {
        if (hdr.ethernet.etherType == TYPE_ARP) {
            arp_conflict_check.apply();
            if (meta.arp_conflict == 1) {
                report_digest.apply();
            }
        }
    }
}

// Deparser
control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        if (hdr.ethernet.etherType == TYPE_ARP) {
            pkt.emit(hdr.arp);
        } else if (hdr.ethernet.etherType == TYPE_IPV4) {
            pkt.emit(hdr.ipv4);
        }
    }
}

// Pipeline
V1Switch(MyParser(), MyIngress(), MyDeparser()) main;
