extern crate pnet;


use pnet::datalink::{self, NetworkInterface};

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, echo_reply, echo_request};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::env;
use std::net::IpAddr;

mod structures;
mod packets;

use structures::Collector;


fn handle_udp_packet(if_name: &str,
                     source: IpAddr,
                     destination: IpAddr,
                     packet: &[u8])
{
    if let Some(udp) = UdpPacket::new(packet) {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                 if_name,
                 source,
                 udp.get_source(),
                 destination,
                 udp.get_destination(),
                 udp.get_length());
    } else {
        println!("[{}]: Malformet udp packet", if_name);
    }
}

fn handle_tcp_packet(if_name: &str,
                     source: IpAddr,
                     destination: IpAddr,
                     packet: &[u8])
{
    if let Some(tcp) = TcpPacket::new(packet) {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                 if_name,
                 source,
                 tcp.get_source(),
                 destination,
                 tcp.get_destination(),
                 packet.len());
    } else {
        println!("[{}]: Malformed tcp packet", if_name);
    }
}

fn handle_icmp_packet(if_name: &str,
                      source: IpAddr,
                      destination: IpAddr,
                      packet: &[u8])
{
    if let Some(icmp) = IcmpPacket::new(packet) {
        match icmp.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                         if_name,
                         source,
                         destination,
                         echo_reply_packet.get_sequence_number(),
                         echo_reply_packet.get_identifier());
            },
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                         if_name,
                         source,
                         destination,
                         echo_request_packet.get_sequence_number(),
                         echo_request_packet.get_identifier());
            },
            _ => {
                println!("[{}]: ICMP packet {} -> {} (type={:?})",
                         if_name,
                         source,
                         destination,
                         icmp.get_icmp_type());
            }
        }
    }
}


fn handle_transport_protocol(collector: &mut Collector,
                             if_name: &str,
                             source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8])
{
    collector.add(source.clone());
    match protocol {
        IpNextHeaderProtocols::Udp => handle_udp_packet(if_name, source, destination, packet),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(if_name, source, destination, packet),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(if_name, source, destination, packet),
        _ => {
            println!("[{}] Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                     if_name,
                     match source {
                         IpAddr::V4(..) => "Ipv4",
                         _ => "Ipv6"
                     },
                     source,
                     destination,
                     protocol,
                     packet.len());
        }
    }

}

fn handle_ipv4_packet(collector: &mut Collector, if_name: &str, ethernet: &EthernetPacket) {
    if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
        handle_transport_protocol(collector,
                                  if_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());

    } else {
        println!("[{}] Malformed Ipv4 packet", if_name);
    }
}

fn handle_ipv6_packet(collector: &mut Collector, if_name: &str, ethernet: &EthernetPacket)
{
    if let Some(header) = Ipv6Packet::new(ethernet.payload())
    {
        handle_transport_protocol(collector,
                                  if_name,
                                  IpAddr::V6(header.get_source()),
                                  IpAddr::V6(header.get_destination()),
                                  header.get_next_header(),
                                  header.payload());
    } else {
        println!("[{}] Malformed Ipv6 packet", if_name);
    }
}

fn handle_arp_packet(if_name: &str, ethernet: &EthernetPacket)
{
    if let Some(header) = ArpPacket::new(ethernet.payload())
        {
            println!("[{}] Arp packet: {}({}) > {}({}); operation: {:?}",
                     if_name,
                     ethernet.get_source(),
                     header.get_sender_proto_addr(),
                     ethernet.get_destination(),
                     header.get_target_proto_addr(),
                     header.get_operation());
        }
    else
    {
        println!("[{}] Malformed Arp packet", if_name);
    }
}

fn handle_packet(collector: &mut Collector, if_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(collector, if_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(collector, if_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(if_name, ethernet),
        _ => {
            println!("[{}] Unknown packet: {} > {}; ethertype: {:?} length: {}",
                     if_name,
                     ethernet.get_source(),
                     ethernet.get_destination(),
                     ethernet.get_ethertype(),
                     ethernet.packet().len())
        }
    }

}

fn main() {
    use pnet::datalink::Channel::Ethernet;
    let count = 10000;
    let part = 200;
    println!("Count: {:?}; Part: {:?}", count, part);

    let iface_name = env::args().nth(1).unwrap();
    println!("Ifname: {}", &iface_name);

    println!("Interfaces: {:?}", datalink::interfaces().as_slice());

    let interface = datalink::interfaces().into_iter()
                        .filter(move |iface: &NetworkInterface| {iface.name == iface_name})
                        .next()
                        .unwrap();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel {}"),
        Err(e) => panic!("packetdump: unable to create channel {}", e)
    };

    let mut net_iter = rx.iter();
    let mut collector = Collector::new(10000);

    while let Ok(packet) = net_iter.next() {
        handle_packet(&mut collector, &interface.name[..], &packet);
        println!("Entropy: {}; Unique: {}; All: {}", collector.get_entropy(),
                 collector.get_unique(), collector.get_all());
    }

}

