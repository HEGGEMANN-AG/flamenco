use std::{
    io::Cursor,
    net::{TcpStream, ToSocketAddrs},
    num::NonZero,
    sync::{Arc, Mutex},
};

use kenobi::cred::{Credentials, Outbound};

use crate::{
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing},
    message::{ReadError, Validation, WriteError, read_202_message, write_202_message},
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    session::{Session202, SessionSetupError},
    sign::SecurityMode,
};

const MINIMUM_TRANSACT_SIZE: u32 = 65536;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum GuestPolicy {
    #[default]
    Disallowed,
    Allowed,
    AllowedInsecurely,
}

#[derive(Debug, Default)]
pub struct Client202 {
    pub requires_signing: bool,
    pub guest_policy: GuestPolicy,
}
impl Client202 {
    pub fn new(require_signing: bool) -> Arc<Self> {
        Self {
            requires_signing: require_signing,
            ..Default::default()
        }
        .into()
    }
    pub fn connect(
        self: Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
        Connection::new(self, addr)
    }
}

#[derive(Debug)]
pub struct ConnectionInner {
    message_id: u64,
    tcp: TcpStream,
}
impl ConnectionInner {
    pub(crate) fn fetch_increment_message_id(&mut self) -> u64 {
        let num = self.message_id;
        self.message_id += 1;
        num
    }
    pub(crate) fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.tcp
    }
}

#[derive(Debug)]
pub struct Connection {
    pub(crate) client: Arc<Client202>,
    pub(crate) inner: Mutex<ConnectionInner>,
    max_transaction_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    server_requires_signing: bool,
}
impl Connection {
    pub fn max_transaction_size(&self) -> u32 {
        self.max_transaction_size
    }
    pub fn max_read_size(&self) -> u32 {
        self.max_read_size
    }
    pub fn max_write_size(&self) -> u32 {
        self.max_write_size
    }
    pub fn server_requires_signing(&self) -> bool {
        self.server_requires_signing
    }
    pub fn setup_session(
        self: Arc<Self>,
        credentials: &Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session202>, SessionSetupError> {
        Session202::new(self, credentials, target_spn)
    }
    pub fn new(
        client: Arc<Client202>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
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
        write_202_message(&mut tcp, None, neg_header, &neg_req, false)?;

        let (header, body) = read_202_message(&mut tcp, Validation::ExpectNone)?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ConnectError::handle_error_body(code, &body));
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
        let server_requires_signing = neg_resp.security_mode == SecurityMode::SigningRequired;
        match neg_resp.dialect {
            Dialect::SMB2020 => {}
            Dialect::Wildcard => unimplemented!(),
            _ => return Err(ConnectError::ServerChoseUnsupportedDialect),
        }

        Ok(Connection {
            client,
            inner: Mutex::new(ConnectionInner { message_id: 1, tcp }),
            max_transaction_size: neg_resp.max_transact_size,
            max_read_size: neg_resp.max_read_size,
            max_write_size: neg_resp.max_write_size,
            server_requires_signing,
        }
        .into())
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
        body: ErrorResponse2,
    },
}
impl ServerError for ConnectError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
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
            ReadError::InvalidSignature
            | ReadError::NotSigned
            | ReadError::InvalidlySignedMessage
            | ReadError::NetBIOS => Self::InvalidMessage,
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
