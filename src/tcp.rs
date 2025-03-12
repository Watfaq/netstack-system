use std::{net::SocketAddr, sync::Arc};

use crate::Nat;

pub struct TcpListener {
    listener: tokio::net::TcpListener,
    nat: Arc<Nat>,
}

impl TcpListener {
    pub fn new(listener: tokio::net::TcpListener, nat: Arc<Nat>) -> Self {
        Self { listener, nat }
    }

    pub fn inner(&self) -> &tokio::net::TcpListener {
        &self.listener
    }

    pub async fn accept(&self) -> std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
        let (stream, remote) = self.listener.accept().await?;
        let remote_port = remote.port();
        let nat_session = match self.nat.look_back(remote_port).await {
            Some(session) => session,
            None => {
                tracing::warn!("session not found, allocated port: {:?}", remote.port());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "session not found",
                ));
            }
        };
        let actual_remote = SocketAddr::new(nat_session.dst, nat_session.dport);
        return Ok((stream, actual_remote));
    }
}
