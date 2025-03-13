#![feature(ip_as_octets)]

mod checksum;
mod error;
mod nat;
mod packet;
mod stack;
mod tcp;
mod udp;

pub use error::StackError;
pub use nat::*;
use stack::SystemStackInner;
pub use tcp::TcpListener;
pub use udp::UdpSocket;
pub type Result<T> = std::result::Result<T, StackError>;

use futures::Sink;
use std::{net::Ipv4Addr, sync::Arc};
use tokio::{
    sync::mpsc::{Receiver, Sender, channel},
    task::JoinHandle,
};

pub struct StackBuilder {
    pub enable_tcp: bool,
    pub enable_udp: bool,
    pub stack_buffer_size: usize,
    pub udp_buffer_size: usize,
    pub inet4_server_addr: Ipv4Addr,
}

impl StackBuilder {
    pub fn new() -> Self {
        Self {
            enable_tcp: true,
            enable_udp: true,
            stack_buffer_size: 1024,
            udp_buffer_size: 1024,
            inet4_server_addr: Ipv4Addr::new(192, 168, 1, 1),
        }
    }

    pub fn enable_tcp(mut self, enable: bool) -> Self {
        self.enable_tcp = enable;
        self
    }

    pub fn enable_udp(mut self, enable: bool) -> Self {
        self.enable_udp = enable;
        self
    }

    pub fn stack_buffer_size(mut self, size: usize) -> Self {
        self.stack_buffer_size = size;
        self
    }

    pub fn udp_buffer_size(mut self, size: usize) -> Self {
        self.udp_buffer_size = size;
        self
    }

    pub fn inet4_addr(mut self, addr: Ipv4Addr) -> Self {
        self.inet4_server_addr = addr;
        self
    }

    pub async fn build(
        self,
    ) -> (
        SystemStack,
        Option<crate::TcpListener>,
        Option<UdpSocket>,
        Sender<Vec<u8>>,
    ) {
        let (stack_tx, stack_rx) = channel(self.stack_buffer_size);

        // udp_writeback_rx -> stack -> tun
        // then the packet is send to network stack
        let (udp_writeback_tx, udp_writeback_rx) = if self.enable_udp {
            let (udp_tx, udp_rx) = channel(self.udp_buffer_size);
            (Some(udp_tx), Some(udp_rx))
        } else {
            (None, None)
        };

        // tun_stream -> stack -> udp_tx
        // then the packet is received by udp_socket
        let (udp_tx, udp_rx) = if self.enable_udp {
            let (udp_tx, udp_rx) = channel(self.udp_buffer_size);
            (Some(udp_tx), Some(udp_rx))
        } else {
            (None, None)
        };

        let (tcp_listener, nat) = if self.enable_tcp {
            (
                tokio::net::TcpListener::bind((self.inet4_server_addr, 0))
                    .await
                    .ok(),
                Some(Arc::new(Nat::new(std::time::Duration::from_secs(60)))),
            )
        } else {
            (None, None)
        };

        let port = tcp_listener
            .as_ref()
            .map(|l| l.local_addr().unwrap().port())
            .unwrap_or(0);

        let tcp_listener = match (tcp_listener, nat.clone()) {
            (Some(listener), Some(nat)) => Some(TcpListener::new(listener, nat)),
            _ => None,
        };

        let stack = SystemStack::new(
            self.inet4_server_addr,
            port,
            stack_rx,
            udp_tx,
            udp_writeback_rx,
            nat,
        )
        .await;

        let udp_socket = match (udp_rx, udp_writeback_tx) {
            (Some(rx), Some(tx)) => Some(UdpSocket::new(rx, tx)),
            _ => None,
        };

        (stack, tcp_listener, udp_socket, stack_tx)
    }
}

pub struct SystemStack {
    inner: SystemStackInner,
}

impl SystemStack {
    async fn new(
        inet4_server_addr: Ipv4Addr,
        tcp4_port: u16,
        data_rx: Receiver<Vec<u8>>,
        udp_tx: Option<Sender<Vec<u8>>>,
        udp_rx: Option<Receiver<Vec<u8>>>,
        tcp_nat: Option<Arc<Nat>>,
    ) -> Self {
        let mut octo = inet4_server_addr.octets();
        octo[3] += 1;
        let inet4_client_addr = Ipv4Addr::from(octo);
        let inner = SystemStackInner::new(
            inet4_server_addr,
            inet4_client_addr,
            tcp4_port,
            data_rx,
            udp_tx,
            udp_rx,
            tcp_nat,
        )
        .await;
        Self { inner }
    }

    pub fn process_loop<W: Sink<Vec<u8>> + Send + Sync + Unpin + 'static>(
        self,
        tun_sink: W,
    ) -> JoinHandle<()>
    where
        W::Error: std::fmt::Debug,
    {
        self.inner.process_loop(tun_sink)
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, ops::Range};

    use smoltcp::wire::{Ipv4Packet, Ipv6Packet, TcpPacket};

    use crate::checksum::UpdateCsum;

    use super::*;

    pub fn process_ip(buf: &mut [u8]) -> anyhow::Result<()> {
        let ip_version = (buf[0] >> 4) & 0x0f;

        let new_sport = 12345;
        let new_dport = 80;
        if ip_version == 4 {
            let new_src = Ipv4Addr::new(192, 168, 1, 100);
            let new_dst = Ipv4Addr::new(10, 0, 0, 1);
            if let Ok(mut mutable_ipv4_packet) = Ipv4Packet::new_checked(&mut buf[..]) {
                let old_src = mutable_ipv4_packet.src_addr();
                let old_dst = mutable_ipv4_packet.dst_addr();
                println!("old src: {}, old dst: {}", old_src, old_dst);

                mutable_ipv4_packet.set_src_addr(new_src);
                mutable_ipv4_packet.update_csum(&old_src.octets(), &new_src.octets());
                mutable_ipv4_packet.set_dst_addr(new_dst);
                mutable_ipv4_packet.update_csum(&old_dst.octets(), &new_dst.octets());
                println!("verify ip csum {}", mutable_ipv4_packet.verify_checksum());

                let ip_header_len = mutable_ipv4_packet.header_len() as usize;

                if let Ok(mut mutable_tcp_packet) =
                    TcpPacket::new_checked(&mut buf[ip_header_len..])
                {
                    // pseudo header
                    mutable_tcp_packet.update_csum(&old_src.octets(), &new_src.octets());
                    mutable_tcp_packet.update_csum(&old_dst.octets(), &new_dst.octets());
                    let old_sport = mutable_tcp_packet.src_port();
                    let old_dport = mutable_tcp_packet.dst_port();
                    mutable_tcp_packet.set_src_port(new_sport);
                    mutable_tcp_packet
                        .update_csum(&old_sport.to_be_bytes(), &new_sport.to_be_bytes());
                    mutable_tcp_packet.set_dst_port(new_dport);
                    mutable_tcp_packet
                        .update_csum(&old_dport.to_be_bytes(), &new_dport.to_be_bytes());

                    println!(
                        "verify tcp csum {}",
                        mutable_tcp_packet.verify_checksum(
                            &smoltcp::wire::IpAddress::Ipv4(new_src),
                            &smoltcp::wire::IpAddress::Ipv4(new_dst)
                        )
                    );
                }
            } else {
                println!("error");
            }
        } else if ip_version == 6 {
            let new_src = Ipv6Addr::new(0, 0, 0, 0, 192, 168, 1, 100);
            let new_dst = Ipv6Addr::new(0, 0, 0, 0, 10, 0, 0, 1);
            if let Ok(mut mutable_ipv6_packet) = Ipv6Packet::new_checked(&mut buf[..]) {
                let old_src = mutable_ipv6_packet.src_addr();
                let old_dst = mutable_ipv6_packet.dst_addr();
                mutable_ipv6_packet.set_src_addr(new_src);
                mutable_ipv6_packet.set_dst_addr(new_dst);

                // Recalculate IPv4 checksum
                let ip_header_len = 0;

                if let Ok(mut mutable_tcp_packet) =
                    TcpPacket::new_checked(&mut buf[ip_header_len..])
                {
                    // pseudo header
                    mutable_tcp_packet.update_csum(&old_src.octets(), &new_src.octets());
                    mutable_tcp_packet.update_csum(&old_dst.octets(), &new_dst.octets());
                    let old_sport = mutable_tcp_packet.src_port();
                    let old_dport = mutable_tcp_packet.dst_port();
                    mutable_tcp_packet.set_src_port(new_sport);
                    mutable_tcp_packet
                        .update_csum(&old_sport.to_be_bytes(), &new_sport.to_be_bytes());
                    mutable_tcp_packet.set_dst_port(new_dport);
                    mutable_tcp_packet
                        .update_csum(&old_dport.to_be_bytes(), &new_dport.to_be_bytes());
                }
            } else {
                println!("error");
            }
        }
        Ok(())
    }

    #[test]
    fn it_works() -> anyhow::Result<()> {
        // Example raw IPv4 + TCP packet (fake data)
        let mut raw_packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28, 0x34, 0xbb, 0x00, 0x00, 0x40, 0x06, 0xb9, 0xd5, 0xc6, 0x12,
            0x00, 0x01, 0xc6, 0x12, 0x00, 0x1a, 0xed, 0x36, 0x01, 0xbb, 0x8f, 0x0c, 0xd7, 0x08,
            0x51, 0x7e, 0x8b, 0xc3, 0x50, 0x10, 0x0f, 0xed, 0xe1, 0x5e, 0x00, 0x00,
        ];
        process_ip(&mut raw_packet[..])?;

        Ok(())
    }

    const CSUM_FIELD: Range<usize> = 10..12;
    const SRC_FIELD: Range<usize> = 12..16;
    const DST_FIELD: Range<usize> = 16..20;

    impl UpdateCsum for &mut [u8] {
        fn update_csum(&mut self, diff_old: &[u8], diff_new: &[u8]) {
            println!("diff_old: {:x?}", diff_old);
            println!("diff_new: {:x?}", diff_new);
            let old_header_csum = u16::from_be_bytes(self[CSUM_FIELD].try_into().unwrap());
            let new_csum = checksum::combine(&[
                !old_header_csum,
                !checksum::data(diff_old),
                checksum::data(diff_new),
            ]);
            let new_header_csum = !new_csum;
            self[CSUM_FIELD].copy_from_slice(&new_header_csum.to_be_bytes());
        }
    }

    #[test]
    fn test_update() {
        let new_dst = [0, 0, 0, 0];
        let mut v = vec![
            0x45, 0x00, 0x00, 0x28, 0x34, 0xbb, 0x00, 0x00, 0x40, 0x06, 0xb9, 0xd5, 0xc6, 0x12,
            0x00, 0x01, 0xc6, 0x12, 0x00, 0x1a, 0xed, 0x36, 0x01, 0xbb, 0x8f, 0x0c, 0xd7, 0x08,
            0x51, 0x7e, 0x8b, 0xc3, 0x50, 0x10, 0x0f, 0xed, 0xe1, 0x5e, 0x00, 0x00,
        ];
        println!(
            "verify: {}",
            Ipv4Packet::new_unchecked(&mut v).verify_checksum()
        );

        // update
        let old_dst = v[DST_FIELD].to_vec();
        v[DST_FIELD].copy_from_slice(&new_dst);
        v.as_mut_slice().update_csum(&old_dst, &new_dst);
        println!(
            "verify: {}",
            Ipv4Packet::new_unchecked(&mut v).verify_checksum()
        );
    }

    #[test]
    fn tttt() {
        let old_src = [1, 2, 3, 4];
        let new_src = [5, 6, 7, 8];
        let mut v = vec![0; 6];
        v[0..4].copy_from_slice(&old_src);
        let orig_csum = !checksum::data(&v[..]);
        v[4..6].copy_from_slice(&orig_csum.to_be_bytes());
        assert_eq!(checksum::data(&v), !0);

        v[0..4].copy_from_slice(&new_src);
        let old_csum = u16::from_be_bytes([v[4], v[5]]);
        let new_csum = checksum::combine(&[
            !old_csum,
            !checksum::data(&old_src),
            checksum::data(&new_src),
        ]);
        let csum = !new_csum;
        v[4..6].copy_from_slice(&csum.to_be_bytes());

        assert_eq!(checksum::data(&v), !0);
    }
}
