use std::{
    collections::HashMap,
    fmt::Display,
    io::{Cursor, ErrorKind},
    num::NonZero,
    ops::DerefMut,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
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
    client::Client202,
    connection::message::IncomingMessage,
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, WriteError},
    negotiate::{Dialect, NegotiateError, NegotiateRequest202, NegotiateResponse},
    session::{Session202, SessionSetupError},
    sign::{SecurityMode, ValidationContext},
};

mod message;

const MINIMUM_TRANSACT_SIZE: u32 = 65536;

pub(crate) type OutstandingRequests = HashMap<u64, Sender<(Arc<SyncHeader202Incoming>, Arc<[u8]>)>>;
type OpenSessions = HashMap<NonZero<u64>, Weak<Session202>>;

struct ConnectionHandle<'ch> {
    write_tcp: &'ch Mutex<OwnedWriteHalf>,
    message_id: &'ch AtomicU64,
    outstanding_requests: &'ch Mutex<OutstandingRequests>,
}
impl<'ch> ConnectionHandle<'ch> {
    pub(crate) async fn signup_message(
        &self,
        mut header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), crate::message::WriteError> {
        let mut wtcp = self.write_tcp.lock().await;
        let next_message_id = self.message_id.fetch_add(1, Ordering::Relaxed);
        header.message_id = next_message_id;
        let (sx, rx) = tokio::sync::oneshot::channel();
        self.outstanding_requests.lock().await.insert(next_message_id, sx);
        message::write_202_message(wtcp.deref_mut(), key, header, msg, add_null).await?;
        Ok(rx.await.expect("dropped sender?"))
    }
}

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
    server_guid: Uuid,
    supports_dfs: bool,
    negotiate_time: u64,
    server_start_time: u64,
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
        }
    }
    pub(crate) async fn signup_message(
        &self,
        header: SyncHeader202Outgoing,
        msg: &impl MessageBody,
        add_null: bool,
        key: Option<[u8; 16]>,
    ) -> Result<(Arc<SyncHeader202Incoming>, Arc<[u8]>), crate::message::WriteError> {
        self.as_handle().signup_message(header, msg, add_null, key).await
    }
    pub(crate) async fn signup_session(&self, session_id: NonZero<u64>, session: Weak<Session202>) -> Result<(), ()> {
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
        self.supports_dfs
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
    ) -> Result<Arc<Session202>, SessionSetupError> {
        Session202::new(self, credentials, target_spn).await
    }
    pub async fn new(
        client: &Arc<Client202>,
        addr: impl ToSocketAddrs,
    ) -> Result<
        (
            impl Future<Output = Result<Arc<Connection>, ConnectError>>,
            impl Future<Output = ()> + Send + 'static,
        ),
        std::io::Error,
    > {
        let (rtcp, wtcp) = TcpStream::connect(addr).await?.into_split();
        let neg_header = SyncHeader202Outgoing::default();

        let message_id = AtomicU64::default();
        let outstanding_requests: Arc<Mutex<OutstandingRequests>> = Arc::default();
        let open_sessions: Arc<RwLock<OpenSessions>> = Arc::default();
        let (shutdown_handle, shutdown_recv) = tokio::sync::oneshot::channel();
        let drive = Self::drive(open_sessions.clone(), outstanding_requests.clone(), rtcp, shutdown_recv);
        let write_tcp = Mutex::new(wtcp);
        Ok((
            Self::finish_connection(
                client.clone(),
                write_tcp,
                message_id,
                open_sessions,
                outstanding_requests,
                neg_header,
                shutdown_handle,
            ),
            drive,
        ))
    }

    async fn finish_connection(
        client: Arc<Client202>,
        write_tcp: Mutex<OwnedWriteHalf>,
        message_id: AtomicU64,
        open_sessions: Arc<RwLock<OpenSessions>>,
        outstanding_requests: Arc<Mutex<OutstandingRequests>>,
        neg_header: SyncHeader202Outgoing,
        shutdown_handle: Sender<()>,
    ) -> Result<Arc<Connection>, ConnectError> {
        let neg_req = NegotiateRequest202 {
            security_mode: client.sent_security_mode(),
        };
        let ch = ConnectionHandle {
            write_tcp: &write_tcp,
            message_id: &message_id,
            outstanding_requests: &outstanding_requests,
        };
        let (header, body) = ch.signup_message(neg_header, &neg_req, false, None).await?;
        if header.command != Command202::Negotiate {
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
        let Dialect::SMB2020 = dialect else {
            return Err(ConnectError::ServerChoseUnsupportedDialect);
        };
        let connection = Connection {
            client,
            outstanding_requests,
            open_sessions,
            message_id,
            write_tcp,
            max_transaction_size: max_transact_size,
            max_read_size,
            max_write_size,
            server_guid,
            supports_dfs: capabilities & 0x01 != 0,
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
                Command202::Negotiate | Command202::SessionSetup | Command202::Logoff
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

fn verify_negotiate_header(header: &SyncHeader202Incoming) -> Result<(), ConnectError> {
    if header.command != Command202::Negotiate
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
            WriteError::MessageTooLong => unreachable!(),
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
