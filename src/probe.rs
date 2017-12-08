use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::collections::HashMap;
use std::thread;

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


use spmc;

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
            match self.sender.send(ipfix) {
                Err(e) => error!("Failed to send ipfix, due to: {}", e),
                _ => {}
            }
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
    lazy_static! {
        static ref FLAGS: Vec<(u16, &'static str)> = vec![
            (TcpFlags::SYN, "SYN"),
            (TcpFlags::FIN, "FIN"),
            (TcpFlags::ACK, "ACK"),
            (TcpFlags::RST, "RST"),
            (TcpFlags::PSH, "PSH"),
            (TcpFlags::URG, "URG")
        ];
    }
    let flag_names: Vec<String> = FLAGS.iter()
        .filter(|ref pair|{ has_flag(flags, pair.0) })
        .map(|ref pair| { pair.1.to_string() }).collect();
    flag_names.join(",")
}

fn has_flag(flags: u16, flag: u16) -> bool {
    (flags & flag) == flag
}


fn create_address(address: IpAddr, port: u16) -> String {
    format!("{}:{}", address, port)
}


pub fn run_probe(sender: Sender<SimpleIpfix>,
                 iface_names: Vec<String>,
                 sampling: u32,
                 processors: u8) -> Vec<thread::JoinHandle<()>> {
    let mut guards = vec![];
    for iface_name in iface_names {
        let (tx, rx) = spmc::channel::<Vec<u8>>();
        let snd = sender.clone();
        run_pcap_processor(snd, rx, processors);
        guards.push(thread::spawn(move || {
            run_sniffer(iface_name.as_str(), sampling, tx);
        }));
    }
    guards
}


pub fn run_pcap_processor(sender: Sender<SimpleIpfix>,
                          receiver: spmc::Receiver<Vec<u8>>,
                          processors: u8) {
    for _ in 0 .. processors {
        let proc_snd = sender.clone();
        let proc_rcv = receiver.clone();

        thread::spawn(move || {
            let probe = Probe::new(proc_snd);
            loop {
                match proc_rcv.recv() {
                    Ok(pkt) => probe.handle_packet(&EthernetPacket::new(&pkt).unwrap()),
                    Err(e) => { 
                        error!("packetprocessor: queue error occured: {}", e);
                        break;
                    }
                }
            }
        });
    }
}


pub fn run_sniffer(iface_name: &str,
                   sampling: u32,
                   sender: spmc::Sender<Vec<u8>>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(|iface| iface.name == iface_name)
        .next().unwrap();

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    if sampling >= 2u32 {
        let mut sample_counter = 0u32;
        loop {
            match rx.next() {
                Ok(packet) => {
                    if sample_counter == 0u32 {
                        let pkt_vec: Vec<u8> = Vec::from(packet);
                        match sender.send(pkt_vec) {
                            Err(e) => {
                                error!("Error occured during send: {}", e);
                                break;
                            },
                            _ => {}
                        }
                    }
                    sample_counter = (sample_counter + 1) % sampling;
                }
                Err(e) => {
                    error!("packetsniffer: unable to receive packet: {}", e);
                    break;
                }
            }
        }
    } else {
        loop {
            match rx.next() {
                Ok(packet) => {
                    match sender.send(Vec::from(packet)) {
                        Err(e) => {
                            error!("Error occured during send: {}", e);
                            break;
                        },
                        _ => {}
                    }
                },
                Err(e) => {
                    error!("packetsniffer: unable to receive packet: {}", e);
                    break;
                }
            }
        }
    }
    drop(rx);
}

