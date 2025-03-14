use futures::{Sink, SinkExt};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

use crate::{Nat, Result, checksum::UpdateCsum};

pub struct SystemStackInner {
    // dnat addr
    inet4_server_addr: Ipv4Addr,
    /// from the listener's point, this will be the remote addr
    /// should under the same subnet of inet4_server_addr
    /// normally, we take it as the next addr of inet4_server_addr
    inet4_client_addr: Ipv4Addr, // saved listener port
    tcp_port: u16,
    /// data receiver from tun
    data_rx: Option<Receiver<Vec<u8>>>,
    /// if Some, then we should process tcp
    tcp_nat: Option<Arc<Nat>>,
    /// udp socket data receiver, should be written back to tun sink
    udp_rx: Option<Receiver<Vec<u8>>>,
    /// udp socket data sender
    udp_tx: Option<Sender<Vec<u8>>>,
}

impl SystemStackInner {
    pub async fn new(
        inet4_server_addr: Ipv4Addr,
        inet4_client_addr: Ipv4Addr,
        tcp_port: u16,
        data_rx: Receiver<Vec<u8>>,
        udp_tx: Option<Sender<Vec<u8>>>,
        udp_rx: Option<Receiver<Vec<u8>>>,
        tcp_nat: Option<Arc<Nat>>,
    ) -> Self {
        let mut octo = inet4_server_addr.octets();
        octo[3] += 1;
        let stack = Self {
            inet4_server_addr,
            tcp_port,
            inet4_client_addr,
            data_rx: Some(data_rx),
            udp_rx,
            udp_tx,
            tcp_nat,
        };

        stack
    }

    // TODO: impl Stream for SystemStack to avoid the ugly loop
    pub fn process_loop<W: Sink<Vec<u8>> + Send + Sync + Unpin + 'static>(
        mut self,
        mut tun_sink: W,
    ) -> JoinHandle<()>
    where
        W::Error: std::fmt::Debug,
    {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(buf) = async {
                        match self.data_rx.as_mut() {
                            Some(rx) => Some(rx.recv().await),
                            None => None,
                        }
                     } => {
                        if let Some(mut buf) = buf {
                            match self.process_ip(&mut buf).await {
                                Ok(true) => {
                                    if let Err(e) = tun_sink.send(buf).await {
                                        tracing::error!("send error: {:?}", e);
                                    }
                                }
                                Ok(false) => {
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("error: {:?}", e);
                                    continue;
                                }
                            }
                        }
                    },
                    Some(buf) = async {
                        match self.udp_rx.as_mut() {
                            Some(rx) => Some(rx.recv().await),
                            None => None,
                        }
                     } => {
                        if let Some(buf) = buf {
                            if let Err(e) = tun_sink.send(buf).await {
                                tracing::error!("send error: {:?}", e);
                            }
                        }
                    }
                }
            }
        })
    }

    /// return if the packet should be written back to tun
    async fn process_ip(&self, buf: &mut [u8]) -> Result<bool> {
        let ip_version = (buf[0] >> 4) & 0x0f;
        if ip_version == 4 {
            return self.process_ipv4(buf).await;
        } else if ip_version == 6 {
            return self.process_ipv6(buf).await;
        }
        Ok(false)
    }

    async fn process_ipv4(&self, buf: &mut [u8]) -> Result<bool> {
        let mut ipv4 = Ipv4Packet::new_checked(&mut *buf)?;
        let src = IpAddr::V4(ipv4.src_addr());
        let dst = IpAddr::V4(ipv4.dst_addr());
        let protocol = ipv4.next_header();
        match protocol {
            IpProtocol::Tcp => {
                let tcp_nat = match &self.tcp_nat {
                    Some(nat) => nat.clone(),
                    None => return Err(crate::StackError::Protocol(IpProtocol::Tcp)),
                };
                let (new_src, new_dst) = match self
                    .process_tcp(tcp_nat, src, dst, &mut ipv4.payload_mut())
                    .await?
                {
                    (IpAddr::V4(new_src), IpAddr::V4(new_dst)) => (new_src, new_dst),
                    _ => {
                        return Err(crate::StackError::Version)?;
                    }
                };
                ipv4.set_src_addr(new_src.into());
                ipv4.set_dst_addr(new_dst.into());
                ipv4.update_csum(src.as_octets(), new_src.as_octets());
                ipv4.update_csum(dst.as_octets(), new_dst.as_octets());
                debug_assert!(ipv4.verify_checksum());
                return Ok(true);
            }
            IpProtocol::Udp => return self.process_udp(buf),
            other => return Err(crate::StackError::Protocol(other)),
        }
    }

    async fn process_ipv6(&self, buf: &mut [u8]) -> Result<bool> {
        let mut ipv6 = Ipv6Packet::new_checked(&mut *buf)?;
        let src = IpAddr::V6(ipv6.src_addr());
        let dst = IpAddr::V6(ipv6.dst_addr());
        let protocol = ipv6.next_header();
        match protocol {
            IpProtocol::Tcp => {
                let tcp_nat = match &self.tcp_nat {
                    Some(nat) => nat.clone(),
                    None => return Err(crate::StackError::Protocol(IpProtocol::Tcp)),
                };
                let (new_src, new_dst) = match self
                    .process_tcp(tcp_nat, src, dst, &mut ipv6.payload_mut())
                    .await?
                {
                    (IpAddr::V6(new_src), IpAddr::V6(new_dst)) => (new_src, new_dst),
                    _ => {
                        return Err(crate::StackError::Version)?;
                    }
                };
                ipv6.set_src_addr(new_src.into());
                ipv6.set_dst_addr(new_dst.into());
                return Ok(true);
            }
            IpProtocol::Udp => return self.process_udp(buf),
            other => return Err(crate::StackError::Protocol(other)),
        }
    }

    // takes old (src, dst), returns the new pair
    async fn process_tcp(
        &self,
        tcp_nat: Arc<Nat>,
        src: IpAddr,
        dst: IpAddr,
        buf: &mut [u8],
    ) -> Result<(IpAddr, IpAddr)> {
        if let Ok(mut tcp) = TcpPacket::new_checked(buf) {
            if src == IpAddr::V4(self.inet4_server_addr) && tcp.src_port() == self.tcp_port {
                // reverse dnat
                let session = tcp_nat.look_back(tcp.dst_port()).await;
                let session = match session {
                    Some(session) => session,
                    None => {
                        tracing::trace!(
                            "{}:{} => {}:{}, flags: ack: {}, fin:{}, syn:{}, rst:{}",
                            src,
                            tcp.src_port(),
                            dst,
                            tcp.dst_port(),
                            tcp.ack(),
                            tcp.fin(),
                            tcp.syn(),
                            tcp.rst()
                        );
                        return Err(crate::StackError::SessionNotFound(tcp.dst_port()))?;
                    }
                };
                let old_src = src;
                let old_dst = dst;
                let old_sport = tcp.src_port();
                let old_dport = tcp.dst_port();
                let new_src = session.dst;
                let new_sport = session.dport;
                let new_dst = session.src;
                let new_dport = session.sport;

                tcp.update_csum(old_src.as_octets(), new_src.as_octets());
                tcp.update_csum(old_dst.as_octets(), new_dst.as_octets());
                tcp.set_src_port(new_sport);
                tcp.set_dst_port(new_dport);
                tcp.update_csum(&old_sport.to_be_bytes(), &new_sport.to_be_bytes());
                tcp.update_csum(&old_dport.to_be_bytes(), &new_dport.to_be_bytes());
                tracing::trace!(
                    "reverse dnat: old ({}:{} => {}:{}), new ({}:{} => {}:{})",
                    old_src,
                    old_sport,
                    old_dst,
                    new_dport,
                    new_src,
                    new_sport,
                    new_dst,
                    new_dport
                );
                debug_assert!(tcp.verify_checksum(&new_src.into(), &new_dst.into()));
                return Ok((new_src, new_dst));
            } else {
                // dnat
                let old_src = src;
                let old_dst = dst;
                let old_sport = tcp.src_port();
                let old_dport = tcp.dst_port();
                let nat_port = tcp_nat
                    .lookup_or_insert(src, old_sport, dst, old_dport)
                    .await;
                let new_src = IpAddr::V4(self.inet4_client_addr);
                let new_sport = nat_port;
                let new_dst = IpAddr::V4(self.inet4_server_addr);
                let new_dport = self.tcp_port;

                // TODO: remove repeated code
                tcp.update_csum(old_src.as_octets(), new_src.as_octets());
                tcp.update_csum(old_dst.as_octets(), new_dst.as_octets());
                tcp.set_src_port(new_sport);
                tcp.set_dst_port(new_dport);
                tcp.update_csum(&old_sport.to_be_bytes(), &new_sport.to_be_bytes());
                tcp.update_csum(&old_dport.to_be_bytes(), &new_dport.to_be_bytes());
                tracing::trace!(
                    "dnat: old ({}:{} => {}:{}), new ({}:{} => {}:{})",
                    old_src,
                    old_sport,
                    old_dst,
                    new_dport,
                    new_src,
                    new_sport,
                    new_dst,
                    new_dport
                );
                debug_assert!(tcp.verify_checksum(&new_src.into(), &new_dst.into()));
                return Ok((new_src, new_dst));
            }
        }
        Ok((src, dst))
    }

    fn process_udp(&self, buf: &mut [u8]) -> Result<bool> {
        self.udp_tx.as_ref().map(|tx| {
            if let Err(e) = tx.try_send(buf.to_vec()) {
                tracing::error!("send error: {:?}", e);
            }
        });
        Ok(false)
    }
}
