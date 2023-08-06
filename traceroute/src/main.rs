use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::udp;
use pnet::packet::ipv4;
use pnet::packet::ethernet;

use std::env;
use std::net;

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
    let payload = [69u8; 32];
    let mut udpbuf = [0u8; 40];
    let mut udppacket = udp::MutableUdpPacket::new(&mut udpbuf).unwrap();
    udppacket.set_source(35553);
    udppacket.set_destination(53335);
    udppacket.set_length(40);
    udppacket.set_payload(&payload);
    println!("udppacket: {:?}", udppacket);

    // ipv4 packet
    let dest = env::args().nth(1).unwrap();
    let mut ipv4buf = [0u8; 60];
    let mut ipv4packet = ipv4::MutableIpv4Packet::new(&mut ipv4buf).unwrap();
    ipv4packet.set_ttl(6);
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
    etherpacket.set_destination(pnet::util::MacAddr::new(0x1a, 0x35, 0x6d, 0x8b, 0xc3, 0xee));
    etherpacket.set_ethertype(ethernet::EtherTypes::Ipv4);
    etherpacket.set_payload(ipv4packet.packet());
    println!("etherpacket: {:?}", etherpacket);

    // connect and send
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("an error occured when creating the channel: {}", e)
    };

    let mut counter = 0;
    loop {
        ipv4packet.set_identification(counter);
        etherpacket.set_payload(ipv4packet.packet());
        counter += 1;
        if let Some(e) = tx.send_to(etherpacket.packet(), Some(interface.clone())) {
            println!("failed to send packet: {:?}", e);
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    // loop {
    //     match rx.next() {
    //         Ok(packet) => {
    //             println!("{:?}", packet);
    //         },
    //         Err(e) => {
    //             panic!("an error occured while reading: {}", e);
    //         }
    //     }
    // }
}
