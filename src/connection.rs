use std::{
    collections::HashMap,
    fmt::Display,
    io::{Cursor, ErrorKind},
    num::NonZero,
    ops::DerefMut,
    sync::{
        Arc, Weak,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
};

#[cfg(feature = "chrono")]
use chrono::{DateTime, Utc};
use kenobi::cred::{Credentials, Outbound};
use tokio::{
    net::{
        TcpStream, ToSocketAddrs,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, RwLock, oneshot::Receiver, oneshot::Sender},
};
use uuid::Uuid;

use crate::{
    client::{Client, ClientCompat},
    connection::message::IncomingMessage,
    credits::Credits,
    error::{ErrorResponse2, ServerError},
    header::{Command, SyncHeaderIncoming, SyncHeaderOutgoing},
    message::{MessageBody, ReadError, WriteError},
    negotiate::{Capabilities, Dialect, NegotiateError, NegotiateRequest, NegotiateResponse},
    session::{Session, SessionSetupError},
    sign::{SecurityMode, ValidationContext},
};

mod message;

const MINIMUM_CREDITS: u16 = 128;
const MINIMUM_TRANSACT_SIZE: u32 = 65536;

pub(crate) type OutstandingRequests = HashMap<u64, Sender<(Arc<SyncHeaderIncoming>, Arc<[u8]>)>>;
type OpenSessions = HashMap<NonZero<u64>, Weak<Session>>;

struct ConnectionHandle<'ch> {
    write_tcp: &'ch Mutex<OwnedWriteHalf>,
    message_id: &'ch AtomicU64,
    outstanding_requests: &'ch Mutex<OutstandingRequests>,
    credits: &'ch Credits,
}
impl<'ch> ConnectionHandle<'ch> {
    pub(crate) async fn signup_message(
        &self,
        mut header: SyncHeaderOutgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(Arc<SyncHeaderIncoming>, Arc<[u8]>), crate::message::WriteError> {
        let mut wtcp = self.write_tcp.lock().await;
        let next_message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        header.message_id = next_message_id;
        let (charge, request) = match self.credits {
            Credits::Simple(c) | Credits::Multi(c) if header.command == Command::Negotiate => (0, 0),
            Credits::Simple(_) => (0, MINIMUM_CREDITS),
            Credits::Multi(atomic) => {
                let charge = msg.calculate_credits();
                let mut current = atomic.load(Ordering::Acquire);
                let credits_after = loop {
                    if current < charge {
                        return Err(WriteError::NotEnoughCredits);
                    }
                    let new = current - charge;
                    match atomic.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => break new,
                        Err(actual) => current = actual,
                    }
                };
                let request = MINIMUM_CREDITS.saturating_sub(credits_after).max(1).max(charge);
                (charge, request)
            }
        };
        header.credit_charge = charge;
        header.credit_request = request;
        let (sx, rx) = tokio::sync::oneshot::channel();
        self.outstanding_requests.lock().await.insert(next_message_id, sx);
        message::write_202_message(wtcp.deref_mut(), key, header, msg, add_null).await?;
        let (header, body) = rx.await.expect("dropped sender?");
        match self.credits {
            Credits::Simple(atomic_u16) => {
                if header.credits > 0 {
                    atomic_u16.fetch_add(1, Ordering::AcqRel);
                }
            }
            Credits::Multi(atomic_u16) => {
                if header.credits > 0 {
                    atomic_u16.fetch_add(header.credits, Ordering::AcqRel);
                }
            }
        }
        Ok((header, body))
    }
}

#[derive(Debug)]
pub struct Connection {
    pub(crate) client: Arc<Client>,
    outstanding_requests: Arc<Mutex<OutstandingRequests>>,
    open_sessions: Arc<RwLock<OpenSessions>>,
    message_id: AtomicU64,
    write_tcp: Mutex<OwnedWriteHalf>,
    max_transaction_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    server_guid: Uuid,
    capabilities: u32,
    negotiate_time: u64,
    server_start_time: u64,
    negotiated_dialect: Dialect,
    credits: Credits,
    /// What the server requires
    requires_signing: bool,
    shutdown_handle: Option<Sender<()>>,
}
impl Connection {
    fn as_handle(&self) -> ConnectionHandle<'_> {
        ConnectionHandle {
            write_tcp: &self.write_tcp,
            message_id: &self.message_id,
            outstanding_requests: &self.outstanding_requests,
            credits: &self.credits,
        }
    }
    pub(crate) async fn signup_message(
        &self,
        header: SyncHeaderOutgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(Arc<SyncHeaderIncoming>, Arc<[u8]>), crate::message::WriteError> {
        self.as_handle().signup_message(header, msg, add_null, key).await
    }
    pub(crate) async fn signup_session(&self, session_id: NonZero<u64>, session: Weak<Session>) -> Result<(), ()> {
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
    pub fn supports_dfs(&self) -> bool {
        self.capabilities & 0x01 != 0
    }
    pub fn server_guid(&self) -> Uuid {
        self.server_guid
    }
    pub fn negotiate_time_raw(&self) -> u64 {
        self.negotiate_time
    }
    #[cfg(feature = "chrono")]
    pub fn negotiate_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.negotiate_time)
    }
    pub fn server_start_time_raw(&self) -> u64 {
        self.server_start_time
    }
    #[cfg(feature = "chrono")]
    pub fn server_start_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.server_start_time)
    }
    pub fn server_requires_signing(&self) -> bool {
        self.requires_signing
    }
    pub async fn setup_session(
        self: Arc<Self>,
        credentials: Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session>, SessionSetupError> {
        Session::new(self, credentials, target_spn).await
    }
    pub fn supports_multi_credits(&self) -> bool {
        self.capabilities & 0x04 != 0
    }
    pub fn dialect(&self) -> Dialect {
        self.negotiated_dialect
    }
    pub async fn new(
        client: &Arc<Client>,
        addr: impl ToSocketAddrs,
    ) -> Result<
        (
            impl Future<Output = Result<Arc<Connection>, ConnectError>>,
            impl Future<Output = ()> + Send + 'static,
        ),
        std::io::Error,
    > {
        let (rtcp, wtcp) = TcpStream::connect(addr).await?.into_split();

        let outstanding_requests: Arc<Mutex<OutstandingRequests>> = Arc::default();
        let open_sessions: Arc<RwLock<OpenSessions>> = Arc::default();
        let (shutdown_handle, shutdown_recv) = tokio::sync::oneshot::channel();
        let drive = Self::drive(open_sessions.clone(), outstanding_requests.clone(), rtcp, shutdown_recv);
        Ok((
            Self::finish_connection(
                client.clone(),
                wtcp,
                open_sessions,
                outstanding_requests,
                shutdown_handle,
            ),
            drive,
        ))
    }

    async fn finish_connection(
        client: Arc<Client>,
        wtcp: OwnedWriteHalf,
        open_sessions: Arc<RwLock<OpenSessions>>,
        outstanding_requests: Arc<Mutex<OutstandingRequests>>,
        shutdown_handle: Sender<()>,
    ) -> Result<Arc<Connection>, ConnectError> {
        let write_tcp = Mutex::new(wtcp);
        let header = SyncHeaderOutgoing::default();
        let message_id = AtomicU64::default();
        let (capabilities, dialects) = match &client.maximum_compatibility {
            ClientCompat::Smb202 => (Capabilities::NONE, vec![Dialect::SMB2020]),
            ClientCompat::Smb210 { .. } => (
                if client.supports_multi_credit() {
                    Capabilities::SMB2_GLOBAL_CAP_LARGE_MTU
                } else {
                    Capabilities::NONE
                },
                vec![Dialect::SMB2020, Dialect::SMB21],
            ),
        };
        let neg_req = NegotiateRequest {
            security_mode: client.sent_security_mode(),
            capabilities,
            dialects: &dialects,
        };
        let ch = ConnectionHandle {
            write_tcp: &write_tcp,
            message_id: &message_id,
            outstanding_requests: &outstanding_requests,
            credits: &Credits::Simple(AtomicU16::default()),
        };
        let (header, body) = ch.signup_message(header, &neg_req, false, None).await?;
        if header.command != Command::Negotiate {
            return Err(ConnectError::InvalidMessage);
        }
        if let Some(code) = NonZero::new(header.status) {
            return Err(ConnectError::handle_error_body(code, &body));
        }
        verify_negotiate_header(&header)?;
        let NegotiateResponse {
            security_mode,
            dialect,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            ..
        } = NegotiateResponse::read_from(&mut Cursor::new(body))?;
        if max_transact_size < MINIMUM_TRANSACT_SIZE
            || max_read_size < MINIMUM_TRANSACT_SIZE
            || max_write_size < MINIMUM_TRANSACT_SIZE
        {
            return Err(ConnectError::MaxMessageSizeInsufficient);
        }
        let max_dialect = match dialect {
            Dialect::SMB2020 => Dialect::SMB2020,
            Dialect::SMB21 => Dialect::SMB21,
            _ => return Err(ConnectError::ServerChoseUnsupportedDialect),
        };
        let credits = match dialect {
            Dialect::SMB2020 => Credits::Simple(AtomicU16::new(header.credits)),
            _ if capabilities & 0x04 != 0 => Credits::Simple(AtomicU16::new(header.credits)),
            _ => Credits::Multi(AtomicU16::new(header.credits)),
        };
        let connection = Connection {
            client,
            outstanding_requests,
            open_sessions,
            message_id,
            write_tcp,
            credits,
            max_transaction_size: max_transact_size,
            max_read_size,
            max_write_size,
            server_guid,
            negotiated_dialect: max_dialect,
            capabilities,
            negotiate_time: system_time,
            server_start_time,
            requires_signing: security_mode == SecurityMode::SigningRequired,
            shutdown_handle: Some(shutdown_handle),
        };
        Ok(Arc::new(connection))
    }

    async fn drive(
        open_sessions: Arc<RwLock<OpenSessions>>,
        outstanding_requests: Arc<Mutex<OutstandingRequests>>,
        mut tcp: OwnedReadHalf,
        mut disconnector: Receiver<()>,
    ) {
        loop {
            let (ctx_sender, ctx_receiver) = tokio::sync::oneshot::channel();
            let read_message = message::read_202_message(&mut tcp, ctx_receiver);
            let read_result = tokio::select! {
                x = read_message => x,
                _ = &mut disconnector => {
                    return;
                }
            };
            let IncomingMessage {
                header,
                content,
                signature_validator,
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
            let session_opt = {
                let lock = open_sessions.read().await;
                header.session_id.and_then(|id| lock.get(&id).cloned())
            };

            let out_of_session = matches!(
                header.command,
                Command::Negotiate | Command::SessionSetup | Command::Logoff
            );

            match session_opt {
                Some(weak) => match Weak::upgrade(&weak) {
                    Some(session) => {
                        let validation_context = ValidationContext {
                            key: Some(*session.session_key()),
                            requires_signing: session.requires_signing(),
                        };
                        if ctx_sender.send(validation_context).is_err() {
                            eprintln!("Validator dropped before receiving context");
                            continue;
                        };

                        if signature_validator.await.is_err() {
                            eprintln!("Bad signature on message");
                            return;
                        };

                        // Validation passed
                        let message_id = header.message_id;
                        let Some(message_sender) = outstanding_requests.lock().await.remove(&message_id) else {
                            eprintln!("Message request not found");
                            continue;
                        };
                        if message_sender.send((header, content)).is_err() {
                            eprintln!("Message receiver for {message_id} closed early");
                        };
                    }
                    None => {
                        eprintln!("Session looked for was removed");
                    }
                },
                None => {
                    if out_of_session {
                        let ctx = ValidationContext {
                            key: None,
                            requires_signing: false,
                        };
                        if ctx_sender.send(ctx).is_err() {
                            eprintln!("Validator dropped for out-of-session message");
                            continue;
                        }

                        let message_id = header.message_id;
                        let Some(message_sender) = outstanding_requests.lock().await.remove(&message_id) else {
                            eprintln!("No outstanding messager for out-of-session message id {message_id}");
                            continue;
                        };
                        if message_sender.send((header, content)).is_err() {
                            eprintln!("Receiver dropped for out-of-session message_id");
                        }
                    } else {
                        eprintln!("received in-session command with no matching session");
                    }
                }
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.shutdown_handle.take().unwrap().send(());
    }
}

fn verify_negotiate_header(header: &SyncHeaderIncoming) -> Result<(), ConnectError> {
    if header.command != Command::Negotiate
        || header.is_async()
        || header.tree_id.is_some()
        || header.session_id.is_some()
    {
        Err(ConnectError::InvalidMessage)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    InvalidMessage,
    MaxMessageSizeInsufficient,
    ServerChoseUnsupportedDialect,
    ServerError { code: NonZero<u32>, body: ErrorResponse2 },
}
impl std::error::Error for ConnectError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            Self::InvalidMessage
            | Self::MaxMessageSizeInsufficient
            | Self::ServerChoseUnsupportedDialect
            | Self::ServerError { .. } => None,
            Self::Io(io) => Some(io),
        }
    }
}
impl Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage => write!(f, "Server returned invalid message"),
            Self::MaxMessageSizeInsufficient => {
                write!(f, "Maximum message size exceeds protocol minimum")
            }
            Self::ServerChoseUnsupportedDialect => write!(f, "Server chose unsupported dialect"),
            Self::ServerError { code, .. } => {
                write!(f, "Server returned error response. Code {code:x}")
            }
            Self::Io(io) => write!(f, "IO error: {io}"),
        }
    }
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
            WriteError::MessageTooLong | WriteError::NotEnoughCredits => unreachable!(),
        }
    }
}
impl From<ReadError> for ConnectError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::Connection(io) => Self::Io(io),
            ReadError::InvalidlySignedMessage | ReadError::InvalidNetbiosLength => Self::InvalidMessage,
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
