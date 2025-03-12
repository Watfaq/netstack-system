use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};

#[derive(Debug)]
pub(super) enum IpPacket<T: AsRef<[u8]>> {
    V4(Ipv4Packet<T>),
    V6(Ipv6Packet<T>),
}

#[allow(unused)]
impl<T: AsRef<[u8]> + Copy> IpPacket<T> {
    pub fn new_checked(packet: T) -> smoltcp::wire::Result<IpPacket<T>> {
        let buffer = packet.as_ref();
        match IpVersion::of_packet(buffer)? {
            IpVersion::Ipv4 => Ok(IpPacket::V4(Ipv4Packet::new_checked(packet)?)),
            IpVersion::Ipv6 => Ok(IpPacket::V6(Ipv6Packet::new_checked(packet)?)),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => IpAddr::from(Ipv4Addr::from(packet.src_addr())),
            IpPacket::V6(ref packet) => IpAddr::from(Ipv6Addr::from(packet.src_addr())),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => IpAddr::from(Ipv4Addr::from(packet.dst_addr())),
            IpPacket::V6(ref packet) => IpAddr::from(Ipv6Addr::from(packet.dst_addr())),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match *self {
            IpPacket::V4(ref packet) => packet.next_header(),
            IpPacket::V6(ref packet) => packet.next_header(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IpPacket<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match *self {
            IpPacket::V4(ref packet) => packet.payload(),
            IpPacket::V6(ref packet) => packet.payload(),
        }
    }
}
