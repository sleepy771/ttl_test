extern crate pnet;

use std::net::IpAddr;
use std::str::FromStr;
use std::borrow::BorrowMut;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

struct Entry<'a> {
    timestamp: u64,
    raw: &'a [u8],
    from: Option<IpAddr>,
    to: Option<IpAddr>,
}

trait Handler {
    fn name(&self) -> &str;

    fn on_tcp_packet(&self, source: &IpAddr, destination: &IpAddr, packet: &TcpPacket)
        -> Result<(), &'static str>;

    fn on_udp_packet(&self, source: &IpAddr, destination: &IpAddr, packet: &UdpPacket)
        -> Result<(), &'static str>;

    fn on_icmp_packet(&self, source: &IpAddr, destination: &IpAddr, packet: &IcmpPacket)
        -> Result<(), &'static str>;

    fn on_arp_packet(&self, packet: &ArpPacket) -> Result<(), &'static str>;

    fn on_unknown(&mut self, packet: &EthernetPacket) -> Result<(), &'static str>;

    fn can_handle_tcp(&self) -> bool;

    fn can_handle_unknown(&self) -> bool;

    fn can_handle_udp(&self) -> bool;

    fn can_handle_icmp(&self) -> bool;

    fn can_handle_arp(&self) -> bool;
}

struct PacketHandler {
    handlers: Vec<Box<Handler>>,
    if_name: String
}

impl PacketHandler {
    fn new(if_name: &str, handlers: Vec<Box<Handler>>) -> PacketHandler
    {
        PacketHandler { handlers: handlers, if_name: String::from_str(if_name).unwrap()}
    }

    fn handle_tcp_packet(&self,
                         source: IpAddr,
                         destination: IpAddr,
                         packet: &[u8])
        -> Result<(), &'static str>
    {
        if let Some(tpc_packet) = TcpPacket::new(packet) {
            self.handlers.iter().filter(|&handler| { handler.can_handle_tcp() })
                .map(|ref mut handler| { handler.can_handle_tcp() });
            Ok(())
        } else {
            Err("Malformed tcp packet")
        }
    }

    fn handle_udp_packet(&self,
                         source: IpAddr,
                         destination: IpAddr,
                         packet: &[u8])
        -> Result<(), &'static str>
    {
        if let Some(udp_packet) = UdpPacket::new(packet) {
            Ok(())
        } else {
            Err("Malformed udp packet")
        }
    }

    fn handle_icmp_packet(&self, source: IpAddr, destination: IpAddr, packet: &[u8]) -> Result<(), &'static str> {
        if let Some(icmp) = IcmpPacket::new(packet) {
            for ref handler in &self.handlers {
                if handler.can_handle_icmp() {
                    handler.on_icmp_packet(&source, &destination, &icmp);
                }
            }
            Ok(())
        } else {
            Err("Malformed icmp packet")
        }
    }

    fn handle_arp_packet(&self, packet: &ArpPacket) -> Result<(), &'static str> {
        if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
            Ok(())
        } else {
            Err("Malformed arp packet")
        }
    }

    fn handle_unknown(packet: &EthernetPacket) -> Result<(), &'static str> {
        unimplemented!()
    }

    fn _handle_transport_protocol(&self,
                                  source: IpAddr,
                                  destination: IpAddr,
                                  protocol: IpNextHeaderProtocol,
                                  packet: &[u8])
        -> Result<(), &'static str>
    {
        match protocol {
            IpNextHeaderProtocols::Udp => {
                self.handle_udp_packet(source, destination, packet);
                Ok(())
            }
            IpNextHeaderProtocols::Tcp => {
                self.handle_tcp_packet(source, destination, packet);
                Ok(())
            }
            IpNextHeaderProtocols::Icmp => {
                self.handle_icmp_packet(source, destination, packet);
                Ok(())
            }
            _ => {
                Err(format!("[{}] Unknown {} packet: {} > {}; protocol: {:?}; length: {}",
                            self.if_name,
                            match source {
                                IpAddr::V4(..) => "Ipv4",
                                _ => "Ipv6"
                            },
                            source,
                            destination,
                            protocol,
                            packet.len()).as_str())
            }
        }
    }

    fn handle_packet(&self, packet: &EthernetPacket)
        -> Result<(), &'static str>
    {
        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(header) = Ipv4Packet::new(packet.payload()) {
                    self._handle_transport_protocol(IpAddr::V4(header.get_source()),
                                                    IpAddr::V4(header.get_destination()),
                                                    header.get_next_level_protocol(),
                                                    header.payload())
                } else {
                    Err("Malformed Ipv4 packet")
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(header) = Ipv6Packet::new(packet.payload()) {
                    self._handle_transport_protocol(IpAddr::V6(header.get_source()),
                                                    IpAddr::V6(header.get_destination()),
                                                    header.get_next_header(),
                                                    header.payload())
                } else {
                    Err("Malformed Ipv6 packet")
                }
            }
            EtherTypes::Arp => {
                if let Some(header) = ArpPacket::new(packet.payload()) {
                    self.handle_arp_packet(&header)
                } else {
                    Err("Malformed Arp packer")
                }
            },
            _ => {
                Err("Unknown packet!")
            }
        }
    }

    fn add_handler<Key: Handler + 'static>(&mut self, handler: Box<Key>)
    {
        self.handlers.push(handler)
    }

    fn can_handle_tcp(&self) -> bool {
        self.handlers.iter().any(|ref handler| { handler.can_handle_tcp() })
    }

    fn can_handle_unknown(&self) -> bool {
        self.handlers.iter().any(|ref handler| { handler.can_handle_unknown() })
    }

    fn can_handle_udp(&self) -> bool {
        self.handlers.iter().any(|ref handler| { handler.can_handle_udp() })
    }

    fn can_handle_icmp(&self) -> bool {
        self.handlers.iter().any(|ref handler| { handler.can_handle_icmp() })
    }

    fn can_handle_arp(&self) -> bool {
        self.handlers.iter().any(|ref handler| { handler.can_handle_arp() })
    }
}

