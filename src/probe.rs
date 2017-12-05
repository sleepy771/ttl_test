
use std::net::IpAddr;
use std::sync::mpsc::Sender;

use pnet::datalink::{self};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::datalink::Channel::Ethernet;

use collector::SimpleIpfix;

struct Probe {
    sender: Sender<SimpleIpfix>,
}

impl Probe {
    pub fn new(sender: Sender<SimpleIpfix>) -> Probe {
        Probe {
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
            Some((source, udp.get_source(), destination, udp.get_destination(), "UDP"))
        } else {
            None
        }
    }

    fn handle_tcp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<SimpleIpfix> {
        if let Some(tcp) = TcpPacket::new(packet) {
            Some((source, tcp.get_source(), destination, tcp.get_destination(), "TCP"))
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
                Some((source, 0, destination, 0, "ICMP"))
            }
            IpNextHeaderProtocols::Icmpv6 => {
                Some((source, 0, destination, 0, "ICMPv6"))
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


pub fn run_probe(sender: Sender<SimpleIpfix>, iface_name: &str, sampling: u32) {

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface| iface.name == iface_name).next().unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let probe = Probe::new(sender);

    if sampling >= 2u32 {
        let mut sample_counter = 0u32;
        loop {
            match rx.next() {
                Ok(packet) => {
                    if sample_counter == 0u32 {
                        probe.handle_packet(&EthernetPacket::new(packet).unwrap())
                    }
                    sample_counter = (sample_counter + 1) % sampling;
                },
                Err(e) => {
                    error!("packetprobe: unable to receive packer: {}", e);
                    break;
                }
            };
        };
    } else {
        loop {
            match rx.next() {
                Ok(packet) => {
                    probe.handle_packet(&EthernetPacket::new(packet).unwrap())
                },
                Err(e) => {
                    error!("packetprobe: unable to receive packer: {}", e);
                    break;
                }
            };
        };

    }   
    drop(rx);
}

