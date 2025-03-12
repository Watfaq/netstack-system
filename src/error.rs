use thiserror::Error;

#[derive(Error, Debug)]
pub enum StackError {
    #[error("session not found, allocated port: {0}")]
    SessionNotFound(u16),
    #[error("not support protocol: {0}")]
    Protocol(smoltcp::wire::IpProtocol),
    #[error("smoltcp error: {0}")]
    Smoltcp(#[from] smoltcp::wire::Error),
    #[error("not supported version")]
    Version,
}
