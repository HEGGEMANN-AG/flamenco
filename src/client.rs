use std::{
    io::{Cursor, ErrorKind},
    net::{TcpStream, ToSocketAddrs},
    num::NonZero,
};

use crate::{
    error,
    header::{Command202, SyncHeader202Outgoing},
    message::{ReadError, WriteError, read_202_message, write_202_message},
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    sign::SecurityMode,
};

const MINIMUM_TRANSACT_SIZE: u32 = 65536;
#[derive(Debug, Default)]
pub struct Client202;
impl Client202 {
    pub fn new() -> Self {
        Client202
    }
    pub fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection<'_>, ConnectError> {
        let mut tcp = TcpStream::connect(addr)?;
        let neg_header = SyncHeader202Outgoing {
            command: Command202::Negotiate,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: 0,
        };
        let neg_req = NegotiateRequest202 {
            capabilities: 0,
            security_mode: SecurityMode::None,
        };
        write_202_message(&mut tcp, &neg_header, &neg_req)?;

        let (header, body) = read_202_message(&mut tcp)?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(match error::ErrorResponse2::from_bytes(&body) {
                Ok(body) => ConnectError::ServerError { code, body },
                Err(error::ParseError::UnexpectedEof) => {
                    std::io::Error::new(ErrorKind::UnexpectedEof, "error body ended early").into()
                }
                Err(
                    error::ParseError::InvalidStructureSize
                    | error::ParseError::ContextNotSupported
                    | error::ParseError::ExcessTrailingBytes,
                ) => ConnectError::InvalidMessage,
            });
        }
        if header.command != Command202::Negotiate || header.message_id != 0 {
            return Err(ConnectError::InvalidMessage);
        }
        let neg_resp = NegotiateResponse::read_from(Cursor::new(body))?;
        if neg_resp.max_transact_size < MINIMUM_TRANSACT_SIZE
            || neg_resp.max_read_size < MINIMUM_TRANSACT_SIZE
            || neg_resp.max_write_size < MINIMUM_TRANSACT_SIZE
        {
            return Err(ConnectError::MaxMessageSizeInsufficient);
        }
        let requires_signing = neg_resp.security_mode == SecurityMode::SigningRequired;
        match neg_resp.dialect {
            Dialect::SMB2020 => {}
            Dialect::Wildcard => unimplemented!(),
            _ => return Err(ConnectError::ServerChoseUnsupportedDialect),
        }

        Ok(Connection {
            client: self,
            message_id: 1,
            tcp,
            max_transact_size: neg_resp.max_transact_size,
            max_read_size: neg_resp.max_read_size,
            max_write_size: neg_resp.max_write_size,
            requires_signing,
        })
    }
}

pub struct Connection<'client> {
    pub(crate) client: &'client Client202,
    message_id: u64,
    pub(crate) tcp: TcpStream,
    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    requires_signing: bool,
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
    MaxMessageSizeInsufficient,
    ServerChoseUnsupportedDialect,
    ServerError {
        code: NonZero<u32>,
        body: error::ErrorResponse2,
    },
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
impl From<NegotiateError> for ConnectError {
    fn from(value: NegotiateError) -> Self {
        match value {
            NegotiateError::InvalidDialect | NegotiateError::InvalidSize => Self::InvalidMessage,
            NegotiateError::Io(io) => Self::Io(io),
        }
    }
}
