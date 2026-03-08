use std::{
    collections::HashMap,
    io::{Cursor, ErrorKind},
    num::NonZero,
    ops::DerefMut,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    net::{
        TcpStream, ToSocketAddrs,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{
        Mutex, RwLock,
        oneshot::{Receiver, Sender},
    },
};

use kenobi::cred::{Credentials, Outbound};

use crate::{
    client::message::UnparsedMessage,
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, WriteError},
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    session::{Session202, SessionSetupError},
    sign::SecurityMode,
};

mod message;

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
    pub fn new(requires_signing: bool) -> Arc<Self> {
        Self {
            requires_signing,
            ..Default::default()
        }
        .into()
    }
    pub async fn connect(
        self: Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
        Connection::new(self, addr).await
    }
}

type OutstandingRequests = HashMap<u64, Sender<(SyncHeader202Incoming, Arc<[u8]>)>>;
type OpenSessions = HashMap<NonZero<u64>, Weak<Session202>>;

#[derive(Debug)]
pub struct Connection {
    pub(crate) client: Arc<Client202>,
    outstanding_requests: Arc<Mutex<OutstandingRequests>>,
    open_sessions: Arc<RwLock<OpenSessions>>,
    message_id: AtomicU64,
    write_tcp: Mutex<OwnedWriteHalf>,
    max_transaction_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    server_requires_signing: bool,
    shutdown_handle: Option<Sender<()>>,
}
impl Connection {
    pub(crate) async fn signup_message(
        &self,
        header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(SyncHeader202Incoming, Arc<[u8]>), crate::message::WriteError> {
        let mut wtcp = self.write_tcp.lock().await;
        Self::signup_message_raw(
            self.outstanding_requests.clone(),
            wtcp.deref_mut(),
            &self.message_id,
            header,
            msg,
            add_null,
            key,
        )
        .await
    }
    pub(crate) async fn signup_session(
        &self,
        session_id: NonZero<u64>,
        session: Weak<Session202>,
    ) -> Result<(), ()> {
        let mut map = self.open_sessions.write().await;
        match map.insert(session_id, session) {
            Some(_) => Err(()),
            None => Ok(()),
        }
    }
    pub(crate) async fn remove_session(&self, session_id: NonZero<u64>) {
        self.open_sessions.write().await.remove(&session_id);
    }
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
    pub async fn setup_session(
        self: Arc<Self>,
        credentials: &Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session202>, SessionSetupError> {
        Session202::new(self, credentials, target_spn).await
    }
    pub async fn new(
        client: Arc<Client202>,
        addr: impl ToSocketAddrs,
    ) -> Result<Arc<Connection>, ConnectError> {
        let (rtcp, mut wtcp) = TcpStream::connect(addr).await?.into_split();
        let neg_header = SyncHeader202Outgoing {
            command: Command202::Negotiate,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: None,
        };
        let neg_req = NegotiateRequest202 {
            capabilities: 0,
            security_mode: SecurityMode::None,
        };
        let message_id = 0.into();
        let outstanding_requests: Arc<Mutex<OutstandingRequests>> = Arc::default();
        let open_sessions: Arc<RwLock<OpenSessions>> = Arc::default();
        let (shutdown_handle, shutdown_recv) = tokio::sync::oneshot::channel();
        tokio::spawn(Self::drive(
            open_sessions.clone(),
            outstanding_requests.clone(),
            rtcp,
            shutdown_recv,
        ));
        let (header, body) = Self::signup_message_raw(
            outstanding_requests.clone(),
            &mut wtcp,
            &message_id,
            neg_header,
            &neg_req,
            false,
            None,
        )
        .await?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ConnectError::handle_error_body(code, &body));
        }
        if header.command != Command202::Negotiate || header.message_id != 0 {
            return Err(ConnectError::InvalidMessage);
        }
        let neg_resp = NegotiateResponse::read_from(&mut Cursor::new(body)).await?;
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
        let write_tcp = Mutex::new(wtcp);
        let connection = Arc::new(Connection {
            client,
            message_id,
            outstanding_requests,
            open_sessions,
            write_tcp,
            max_transaction_size: neg_resp.max_transact_size,
            max_read_size: neg_resp.max_read_size,
            max_write_size: neg_resp.max_write_size,
            server_requires_signing,
            shutdown_handle: Some(shutdown_handle),
        });
        Ok(connection)
    }
    #[allow(clippy::too_many_arguments)]
    async fn signup_message_raw(
        pending_requests: Arc<Mutex<OutstandingRequests>>,
        write_tcp: &mut OwnedWriteHalf,
        id: &AtomicU64,
        mut header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(SyncHeader202Incoming, Arc<[u8]>), crate::message::WriteError> {
        let next_message_id = id.fetch_add(1, Ordering::Relaxed);
        header.message_id = next_message_id;
        let (sx, rx) = tokio::sync::oneshot::channel();
        pending_requests.lock().await.insert(next_message_id, sx);
        message::write_202_message(write_tcp, key, header, msg, add_null).await?;
        Ok(rx.await.expect("dropped sender?"))
    }
    async fn drive(
        open_sessions: Arc<RwLock<OpenSessions>>,
        outstanding_requests: Arc<Mutex<OutstandingRequests>>,
        mut tcp: OwnedReadHalf,
        mut disconnector: Receiver<()>,
    ) {
        loop {
            let (key_sender, key_receiver) = tokio::sync::oneshot::channel();
            let read_message = message::read_202_message(&mut tcp, key_receiver);
            let read_result = tokio::select! {
                x = read_message => x,
                _ = &mut disconnector => {
                    return;
                }
            };
            let UnparsedMessage {
                header,
                content,
                signature_validator: signature_verifier,
            } = match read_result {
                Ok(v) => v,
                Err(ReadError::Connection(io)) if io.kind() == ErrorKind::ConnectionReset => {
                    break;
                }
                Err(err) => {
                    eprintln!("Error reading message: {err:?}");
                    continue;
                }
            };
            let session = {
                let lock = open_sessions.read().await;
                NonZero::new(header.session_id).and_then(|id| lock.get(&id).cloned())
            };
            if let Some(maybe_session) = session {
                if let Some(session) = maybe_session.upgrade() {
                    key_sender
                        .send(Some(*session.session_key()))
                        .expect("validation side task removed");
                    let Ok(()) = signature_verifier.await else {
                        eprintln!("Bad signature on message");
                        return;
                    };
                } else {
                    eprintln!("Session closed");
                    continue;
                }
                let message_id = header.message_id;
                let Some(message_sender) = outstanding_requests.lock().await.remove(&message_id)
                else {
                    eprintln!("Message request not found");
                    continue;
                };
                if message_sender.send((header, content)).is_err() {
                    eprintln!("Message receiver for {message_id} closed early");
                };
            } else if matches!(
                header.command,
                Command202::Negotiate | Command202::SessionSetup | Command202::Logoff
            ) {
                let message_sender = outstanding_requests
                    .lock()
                    .await
                    .remove(&header.message_id)
                    .unwrap();
                let _ = message_sender.send((header, content));
            } else {
                eprintln!("Logged in command with no session");
            }
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.shutdown_handle.take().unwrap().send(());
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
            ReadError::InvalidlySignedMessage | ReadError::NetBIOS => Self::InvalidMessage,
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
