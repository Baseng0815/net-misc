use rand::prelude::*;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::udp;
use pnet::packet::ipv4;
use pnet::packet::icmp;
use pnet::packet::ethernet;

use std::env;
use std::net;

const MAX_HOPS: u8 = 16;
const PORT_SRC: u16 = 13371;
const PORT_DST: u16 = 42042;

#[derive(Debug)]
struct ResponseEntry {
    addr: net::Ipv4Addr,
    ident: u16
}

fn main() {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface| iface.is_running() && !iface.is_loopback()).next().unwrap();
    println!("using interface {:?}", interface.name);

    let interface_addr: net::Ipv4Addr = match interface.ips.get(0).unwrap().ip() {
        net::IpAddr::V4(ipv4a) => ipv4a,
        _ => panic!("couldn't get local ipv4 address")
    };
    println!("local ip address: {:?}", interface_addr);

    // construct packets
    // udp packet
    let mut payload = [0u8; 32];
    for i in 0u8..32u8 {
        payload[i as usize] = 0x40u8 + i;
    }
    let mut udpbuf = [0u8; 40];
    let mut udppacket = udp::MutableUdpPacket::new(&mut udpbuf).unwrap();
    udppacket.set_source(PORT_SRC);
    udppacket.set_destination(PORT_DST);
    udppacket.set_length(40);
    udppacket.set_payload(&payload);
    // udppacket.set_checksum(0x0B25); not necessary
    println!("udppacket: {:?}", udppacket);

    // ipv4 packet
    let dest = env::args().nth(1).unwrap();
    let mut ipv4buf = [0u8; 60];
    let mut ipv4packet = ipv4::MutableIpv4Packet::new(&mut ipv4buf).unwrap();
    ipv4packet.set_source(interface_addr);
    ipv4packet.set_destination(dest.parse().unwrap());
    ipv4packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ipv4packet.set_version(4);
    ipv4packet.set_header_length(5);
    ipv4packet.set_total_length(60);
    ipv4packet.set_payload(&udppacket.packet());
    println!("ipv4packet: {:?}", ipv4packet);

    let mut ethernetbuf = [0u8; 74];
    let mut etherpacket = ethernet::MutableEthernetPacket::new(&mut ethernetbuf).unwrap();
    etherpacket.set_source(interface.mac.unwrap());
    // etherpacket.set_destination(pnet::util::MacAddr::broadcast());
    etherpacket.set_destination(pnet::util::MacAddr::new(0x6c, 0xff, 0xce, 0xcd, 0xa2, 0x9c));
    etherpacket.set_ethertype(ethernet::EtherTypes::Ipv4);
    etherpacket.set_payload(ipv4packet.packet());
    println!("etherpacket: {:?}", etherpacket);

    // connect and send
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("an error occured when creating the channel: {}", e)
    };

    let mut responses: Vec<ResponseEntry> = Vec::new();
    for ttl in 1..=MAX_HOPS {
        let ident = ttl as u16;
        ipv4packet.set_ttl(ttl);
        ipv4packet.set_identification(ident);
        ipv4packet.set_checksum(ipv4::checksum(&ipv4packet.to_immutable()));
        etherpacket.set_payload(ipv4packet.packet());
        tx.send_to(etherpacket.packet(), Some(interface.clone()));
    }

    let mut counter = 0;
    while counter < MAX_HOPS {
        match rx.next() {
            Ok(packet) => {
                let response_ether = ethernet::EthernetPacket::new(packet).unwrap();
                if response_ether.get_ethertype() != ethernet::EtherTypes::Ipv4 {
                    break;
                }

                let response_ipv4 = ipv4::Ipv4Packet::owned(response_ether.payload().to_vec()).unwrap();
                if response_ipv4.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Icmp {
                    break;
                }

                let response_icmp = icmp::IcmpPacket::new(response_ipv4.payload()).unwrap();
                let data = &response_icmp.payload()[4..];
                let prev_ipv4_header = ipv4::Ipv4Packet::new(data).unwrap();

                let data = &data[((prev_ipv4_header.get_header_length() * 4) as usize)..];
                let port_src = data[1] as u16 | (data[0] as u16) << 8;
                let port_dst = data[3] as u16 | (data[2] as u16) << 8;

                // ICMP packets belong to our request only if ports match
                if port_src != PORT_SRC && port_dst == PORT_DST {
                    continue;
                }

                counter += 1;

                if response_icmp.get_icmp_type() == icmp::IcmpTypes::TimeExceeded {
                    responses.push(ResponseEntry {
                        addr: response_ipv4.get_source(), ident: prev_ipv4_header.get_identification()
                    });
                }
            },
            Err(e) => {
                panic!("an error occured while reading: {}", e);
            }
        }
    }

    responses.sort_by_key(|entry| entry.ident);
    for (i, val) in responses.iter().enumerate() {
        println!("{} {:?}", val.ident, val.addr);
    }
}
