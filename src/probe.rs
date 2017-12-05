
extern crate pnet;

use std::env;
use std::io::{self, Write};
use std::process;
use std::net::IpAddr;
use std::sync::mpsc::Sender;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::datalink::Channel::Ethernet;

use collector::SimpleIpfix;

struct Probe {
    sender: Sender<SimpleIpfix>,
    ifname: String
}

impl Probe {
    pub fn new(ifname: String, sender: Sender<SimpleIpfix>) -> Probe {
        Probe {
            ifname: ifname,
            sender: sender
        }
    }

    fn handle_packet(&self, ethernet: &EthernetPacket) {
        let ipfix = match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.handle_ipv4_packet(ethernet),
            EtherTypes::Ipv6 => self.handle_ipv6_packet(ethernet),
            _ => {
                None
            }
        };

        if let Some(ipfix) = ipfix {
            self.sender.send(ipfix).unwrap();
        }
    }

    fn handle_udp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<SimpleIpfix> {
        if let Some(udp) = UdpPacket::new(packet) {
            Some((source, udp.get_source(), destination, udp.get_destination(), IpNextHeaderProtocols::Udp))
        } else {
            None
        }
    }

    fn handle_tcp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<SimpleIpfix> {
        if let Some(tcp) = TcpPacket::new(packet) {
            Some((source, tcp.get_source(), destination, tcp.get_destination(), IpNextHeaderProtocols::Tcp))
        } else {
            None
        }
    }

    fn handle_transport_protocol(&self,
                                 source: IpAddr,
                                 destination: IpAddr,
                                 protocol: IpNextHeaderProtocol,
                                 packet: &[u8]) -> Option<SimpleIpfix> {
        match protocol {
            IpNextHeaderProtocols::Udp => {
                self.handle_udp_packet(source, destination, packet)
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_tcp_packet(source, destination, packet)
            }
            IpNextHeaderProtocols::Icmp => {
                Some((source, 0, destination, 0, IpNextHeaderProtocols::Icmp))
            }
            IpNextHeaderProtocols::Icmpv6 => {
                Some((source, 0, destination, 0, IpNextHeaderProtocols::Icmpv6))
            }
            _ => {
                None
            }

        }
    }

    fn handle_ipv4_packet(&self, ethernet: &EthernetPacket) -> Option<SimpleIpfix> {
        let header = Ipv4Packet::new(ethernet.payload());
        if let Some(header) = header {
            self.handle_transport_protocol(IpAddr::V4(header.get_source()),
                                           IpAddr::V4(header.get_destination()),
                                           header.get_next_level_protocol(),
                                           header.payload())
        } else {
            None
        }
    }

    fn handle_ipv6_packet(&self, ethernet: &EthernetPacket) -> Option<SimpleIpfix> {
        let header = Ipv6Packet::new(ethernet.payload());
        if let Some(header) = header {
            self.handle_transport_protocol(IpAddr::V6(header.get_source()),
                                           IpAddr::V6(header.get_destination()),
                                           header.get_next_header(),
                                           header.payload())
        } else {
            None
        }
    }
}


pub fn run_probe(sender: Sender<SimpleIpfix>, iface_name: &str) {

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface| iface.name == iface_name).next().unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let ifname = interface.name[..].to_string();
    let probe = Probe::new(ifname, sender);

    loop {
        match rx.next() {
            Ok(packet) => probe.handle_packet(&EthernetPacket::new(packet).unwrap()),
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

