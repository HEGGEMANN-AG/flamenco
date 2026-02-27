use std::{
    net::{TcpStream, ToSocketAddrs},
    num::NonZero,
};

use crate::{
    header::{Command202, SyncHeader202},
    message::{ReadError, WriteError, read_202_message, write_202_message},
    negotiate::NegotiateRequest202,
};

#[derive(Debug, Default)]
pub struct Client202;
impl Client202 {
    pub fn new() -> Self {
        Client202
    }
    pub fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection<'_>, ConnectError> {
        let mut tcp = TcpStream::connect(addr)?;
        let neg_header = SyncHeader202 {
            status: 0,
            command: Command202::Negotiate,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let neg_req = NegotiateRequest202 { capabilities: 0 };
        write_202_message(&mut tcp, &neg_header, &neg_req)?;

        let (header, body) = read_202_message(&mut tcp)?;
        if let Some(stat) = NonZero::new(header.status) {
            return Err(ConnectError::ServerError(stat));
        }
        if header.command != Command202::Negotiate || header.message_id != 0 {
            return Err(ConnectError::InvalidMessage);
        }

        Ok(Connection {
            client: self,
            message_id: 1,
            tcp,
        })
    }
}

pub struct Connection<'client> {
    client: &'client Client202,
    message_id: u64,
    tcp: TcpStream,
}
impl Connection<'_> {
    fn fetch_increment_message_id(&mut self) -> u64 {
        let num = self.message_id;
        self.message_id += 1;
        num
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    InvalidMessage,
    ServerError(NonZero<u32>),
}
impl From<std::io::Error> for ConnectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<WriteError> for ConnectError {
    fn from(value: WriteError) -> Self {
        match value {
            WriteError::Connection(io) => Self::Io(io),
            WriteError::MessageTooLong => unreachable!(),
        }
    }
}
impl From<ReadError> for ConnectError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::Connection(io) => Self::Io(io),
        }
    }
}
