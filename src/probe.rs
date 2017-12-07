
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::collections::HashMap;

use pnet::datalink::{self};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::{IcmpTypes, IcmpPacket, IcmpType};
use pnet::datalink::Channel::Ethernet;

use collector::SimpleIpfix;

lazy_static! {
    static ref ICMP_CONVERT: HashMap<IcmpType, &'static str> = {
        let mut map = HashMap::new();
        map.insert(IcmpTypes::EchoReply, "EchoReply");
        map.insert(IcmpTypes::DestinationUnreachable, "DestinationUnreachable");
        map.insert(IcmpTypes::SourceQuench, "SourceQuench");
        map.insert(IcmpTypes::RedirectMessage, "RedirectMessage");
        map.insert(IcmpTypes::EchoRequest, "EchoRequest");
        map.insert(IcmpTypes::RouterAdvertisement, "RouterAdvertisement");
        map.insert(IcmpTypes::RouterSolicitation, "RouterSolicitation");
        map.insert(IcmpTypes::TimeExceeded, "TimeExceeded");
        map.insert(IcmpTypes::ParameterProblem, "ParameterProblem");
        map.insert(IcmpTypes::Timestamp, "Timestamp");
        map.insert(IcmpTypes::TimestampReply, "TimestampReply");
        map.insert(IcmpTypes::InformationRequest, "InformationRequest");
        map.insert(IcmpTypes::InformationReply, "InformationReply");
        map.insert(IcmpTypes::AddressMaskRequest, "AddressMaskRequest");
        map.insert(IcmpTypes::AddressMaskReply, "AddressMaskReply");
        map.insert(IcmpTypes::Traceroute, "Traceroute");
        map
    };
}


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
            Some(
                (
                    create_address(source, udp.get_source()),
                    create_address(destination, udp.get_destination()),
                    "UDP",
                    vec![]
                )
                )
        } else {
            None
        }
    }

    fn handle_tcp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<SimpleIpfix> {
        if let Some(tcp) = TcpPacket::new(packet) {
            let flags = parse_flags(tcp.get_flags());
            Some(
                (
                    create_address(source, tcp.get_source()),
                    create_address(destination, tcp.get_destination()),
                    "TCP",
                    vec![("flags", flags)]
                )
                )
        } else {
            None
        }
    }

    fn handle_icmp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Option<SimpleIpfix> {
        if let Some(icmp) = IcmpPacket::new(packet) {
            let icmp_type = icmp.get_icmp_type();
            let type_name: String = match ICMP_CONVERT.get(&icmp_type) {
                Some(name) => name.to_string(),
                None => format!("{}", icmp.get_icmp_type().0)
            };
            Some(
                (
                    format!("{}", source),
                    format!("{}", destination),
                    "ICMP",
                    vec![("type", type_name), ("code", format!("{}", icmp.get_icmp_code().0))]
                )
                )
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
                self.handle_icmp_packet(source, destination, packet)
            }
            IpNextHeaderProtocols::Icmpv6 => {
                Some((format!("{}", source), format!("{}", destination), "ICMPv6", vec![]))
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

fn parse_flags(flags: u16) -> String {
    let flags_to_check: Vec<(u16, &'static str)> = vec![
        (TcpFlags::SYN, "SYN"),
        (TcpFlags::FIN, "FIN"),
        (TcpFlags::ACK, "ACK"),
        (TcpFlags::RST, "RST"),
        (TcpFlags::PSH, "PSH"),
        (TcpFlags::URG, "URG")
    ];
    let flag_names: Vec<String> = flags_to_check.into_iter().filter(|&(flag, symbol)|{ has_flag(flags, flag) }).map(|(flag, symbol)| { symbol.to_string() }).collect();
    flag_names.join(",")
}

fn has_flag(flags: u16, flag: u16) -> bool {
    (flags & flag) == flag
}


fn create_address(address: IpAddr, port: u16) -> String {
    format!("{}:{}", address, port)
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

