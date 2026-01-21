use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU16},
};

use dashmap::DashMap;

#[derive(Clone, Debug)]
pub struct Session {
    pub src: core::net::IpAddr,
    pub sport: u16,
    pub dst: core::net::IpAddr,
    pub dport: u16,
    pub time: u64,
}

pub struct Nat {
    port_index: AtomicU16,
    addr_to_port: Arc<DashMap<SocketAddr, u16>>,
    port_to_session: Arc<DashMap<u16, Session>>,
}

impl Nat {
    pub fn new(timeout: std::time::Duration) -> Self {
        let addr_to_port: Arc<DashMap<SocketAddr, u16>> =
            Arc::new(DashMap::new());
        let port_to_session: Arc<DashMap<u16, Session>> =
            Arc::new(DashMap::new());

        let addr_to_port_check = addr_to_port.clone();
        let port_to_session_check = port_to_session.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(timeout).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let mut to_remove = Vec::new();
                for entry in addr_to_port_check.iter() {
                    let addr = entry.key();
                    let port = entry.value();
                    if let Some(session) = port_to_session_check.get(port) {
                        if now - session.time > timeout.as_secs() {
                            to_remove.push(addr.clone());
                        }
                    }
                }
                for addr_port in to_remove {
                    addr_to_port_check.remove(&addr_port);
                    port_to_session_check.remove(&addr_port.port());
                }
            }
        });

        Self {
            port_index: AtomicU16::new(10000),
            addr_to_port,
            port_to_session,
        }
    }

    pub async fn look_back(&self, port: u16) -> Option<Session> {
        self.port_to_session.get(&port).map(|s| s.clone())
    }

    pub async fn lookup_or_insert(
        &self,
        src: core::net::IpAddr,
        sport: u16,
        dst: core::net::IpAddr,
        dport: u16,
    ) -> u16 {
        let addr_port = SocketAddr::new(src, sport);

        if let Some(port) = self.addr_to_port.get(&addr_port) {
            return *port;
        }

        // TODO: use 32 to avoid overflow
        let port = self
            .port_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.addr_to_port.insert(addr_port, port);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.port_to_session.insert(
            port,
            Session {
                src,
                sport,
                dst,
                dport,
                time,
            },
        );

        port
    }

    pub async fn remove(&self, port: u16) {
        if let Some((_, session)) = self.port_to_session.remove(&port) {
            let addr_port = SocketAddr::new(session.src, session.sport);
            self.addr_to_port.remove(&addr_port);
        }
    }
}
