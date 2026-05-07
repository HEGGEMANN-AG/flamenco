use std::{
    fmt::{Debug, Display},
    io::{Cursor, Read, Seek, SeekFrom},
    num::NonZero,
    sync::Arc,
};

use kenobi::{
    client::{ClientBuilder, InitializeError, StepOut},
    cred::{Credentials, Outbound},
};

use crate::{
    ReadIntLe,
    client::GuestPolicy,
    connection::Connection,
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing, SyncHeaderIncoming},
    message::{MessageBody, ReadError as MsgReadError, WriteError as MsgWriteError},
    sign::SecurityMode,
    tree::{TreeConnectError, TreeConnection},
};

const ERROR_MORE_PROCESSING_REQUIRED: u32 = 0xC0000016;

pub struct Session202 {
    session_key: [u8; 16],
    pub(crate) id: NonZero<u64>,
    pub(crate) connection: Arc<Connection>,
    flags: SessionFlags,
    requires_signing: bool,
}
impl Debug for Session202 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session202")
            .field("session_key", &"REDACTED")
            .field("id", &self.id)
            .field("connection", &self.connection)
            .field("flags", &self.flags)
            .field("requires_signing", &self.requires_signing)
            .finish()
    }
}
impl Session202 {
    pub fn requires_signing(&self) -> bool {
        self.requires_signing
    }
    pub(crate) fn session_key(&self) -> &[u8; 16] {
        &self.session_key
    }
    pub async fn new(
        connection: Arc<Connection>,
        cred: Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session202>, SessionSetupError> {
        let mut auth_context = match ClientBuilder::new_from_credentials(cred, target_spn)
            .request_mutual_auth()
            .request_delegation()
            .initialize()
            .map_err(SessionSetupError::InitializeSecurityContext)?
        {
            StepOut::Pending(pending) => pending,
            StepOut::Finished(_c) => unreachable!(),
        };
        let mut session_id = None;
        loop {
            let client = &connection.client;
            let header = SyncHeader202Outgoing {
                command: Command202::SessionSetup,
                credit_charge: 1,
                credit_request: 1,
                credits: 0,
                flags: 0,
                next_command: None,
                message_id: 0,
                tree_id: None,
                session_id,
            };
            let body = SessionSetupRequest {
                security_mode: if client.requires_signing {
                    SecurityMode::SigningRequired
                } else {
                    SecurityMode::SigningEnabled
                },
                capabilities: 0,
                previous_session_id: 0,
                buffer: auth_context.next_token(),
            };
            let (header, body) = connection.signup_message(header, &body, false, None).await?;
            // Lookup session ID
            if let Some(code) = NonZero::new(header.status)
                && code.get() != ERROR_MORE_PROCESSING_REQUIRED
            {
                return Err(SessionSetupError::handle_error_body(code, &body));
            }
            verify_session_setup_header(&header)?;
            let SessionSetupResponse { flags, sec_buffer } = SessionSetupResponse::read_from(Cursor::new(body))?;

            auth_context = match auth_context
                .step(&sec_buffer)
                .map_err(SessionSetupError::InitializeSecurityContext)?
            {
                StepOut::Pending(p) => p,
                StepOut::Finished(context) => {
                    let session_key = *context
                        .session_key()
                        .first_chunk::<16>()
                        .ok_or(SessionSetupError::SessionKeyTooShort)?;
                    if flags == SessionFlags::Guest {
                        match client.guest_policy {
                            GuestPolicy::Disallowed => {
                                return Err(SessionSetupError::DisallowedGuestAccess);
                            }
                            GuestPolicy::AllowedInsecurely if client.requires_signing => {
                                return Err(SessionSetupError::DisallowedGuestAccess);
                            }
                            _ => {}
                        }
                    }
                    let requires_signing = match flags {
                        SessionFlags::None => connection.server_requires_signing() || client.requires_signing,
                        SessionFlags::Guest => client.requires_signing,
                        SessionFlags::Anonymous => false,
                    };
                    let Some(id) = header.session_id else {
                        return Err(SessionSetupError::InvalidMessage);
                    };
                    let session = Session202 {
                        flags,
                        requires_signing,
                        id,
                        session_key,
                        connection,
                    };
                    let as_arc = Arc::new(session);
                    as_arc
                        .connection
                        .signup_session(id, Arc::downgrade(&as_arc))
                        .await
                        .unwrap();
                    return Ok(as_arc);
                }
            };
            session_id = header.session_id;
        }
    }
    pub async fn tree_connect(self: Arc<Self>, share_path: &str) -> Result<Arc<TreeConnection>, TreeConnectError> {
        TreeConnection::new(self, share_path).await
    }
    pub async fn logoff(self) {
        let logoff_header = SyncHeader202Outgoing {
            command: Command202::Logoff,
            credit_charge: 1,
            credit_request: 1,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: None,
            session_id: Some(self.id),
        };
        let key = self.requires_signing().then_some(self.session_key);
        self.connection.remove_session(self.id).await;
        let Ok((h, _)) = self
            .connection
            .signup_message(logoff_header, &LogoffRequest, false, key)
            .await
        else {
            return;
        };
        let _ = verify_logoff_header(&h);
    }
}

fn verify_session_setup_header(header: &SyncHeaderIncoming) -> Result<(), SessionSetupError> {
    if header.command != Command202::SessionSetup || header.is_async() || header.tree_id.is_some() {
        Err(SessionSetupError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn verify_logoff_header(header: &SyncHeaderIncoming) -> Result<(), LogoffError> {
    if header.command != Command202::Logoff || header.is_async() {
        Err(LogoffError::InvalidMessage)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
enum LogoffError {
    InvalidMessage,
}
#[derive(Debug)]
pub enum SessionSetupError {
    Io(std::io::Error),
    InitializeSecurityContext(InitializeError),
    DisallowedGuestAccess,
    NotEnoughCredits,
    AuthContextTokenTooLong,
    SessionKeyTooShort,
    InvalidMessage,
    ServerError { code: NonZero<u32>, body: ErrorResponse2 },
}
impl std::error::Error for SessionSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InitializeSecurityContext(_)
            | Self::DisallowedGuestAccess
            | Self::AuthContextTokenTooLong
            | Self::NotEnoughCredits
            | Self::SessionKeyTooShort
            | Self::InvalidMessage
            | Self::ServerError { .. } => None,
        }
    }
}
impl Display for SessionSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO Error: {error}"),
            Self::InitializeSecurityContext(_) => write!(f, "GSSAPI error"),
            Self::DisallowedGuestAccess => write!(f, "Guest access is not allowed or signing is required"),
            Self::AuthContextTokenTooLong => write!(f, "Auth context by the server was too long"),
            Self::SessionKeyTooShort => write!(f, "Session key by GSSAPI was too short"),
            Self::InvalidMessage => write!(f, "Server sent an invalid message"),
            Self::NotEnoughCredits => write!(f, "Not enough credits for this operation"),
            Self::ServerError { code, .. } => write!(f, "Server sent error code {code}"),
        }
    }
}
impl From<MsgWriteError> for SessionSetupError {
    fn from(value: MsgWriteError) -> Self {
        match value {
            MsgWriteError::NotEnoughCredits => Self::NotEnoughCredits,
            MsgWriteError::Connection(error) => Self::Io(error),
            MsgWriteError::MessageTooLong => Self::AuthContextTokenTooLong,
        }
    }
}
impl From<MsgReadError> for SessionSetupError {
    fn from(value: MsgReadError) -> Self {
        match value {
            MsgReadError::InvalidlySignedMessage | MsgReadError::InvalidNetbiosLength => Self::InvalidMessage,
            MsgReadError::Connection(io) => Self::Io(io),
        }
    }
}
impl From<ReadError> for SessionSetupError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::InvalidFlags | ReadError::InvalidSize => Self::InvalidMessage,
            ReadError::Io(io) => Self::Io(io),
        }
    }
}
impl ServerError for SessionSetupError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
}
impl From<std::io::Error> for SessionSetupError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
struct SessionSetupRequest<'buf> {
    pub security_mode: SecurityMode,
    pub capabilities: u32,
    pub previous_session_id: u64,
    pub buffer: &'buf [u8],
}
impl MessageBody for SessionSetupRequest<'_> {
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&25u16.to_le_bytes());
        // flags
        w.push(0);
        // security mode
        w.extend_from_slice(&[self.security_mode.to_value()]);
        w.extend_from_slice(&self.capabilities.to_le_bytes());
        // channel
        w.extend_from_slice(&0u32.to_le_bytes());

        let secbuf_offset: u16 = 64 + 24;
        w.extend_from_slice(&secbuf_offset.to_le_bytes());
        let secbuf_len: u16 = self.buffer.len().try_into().unwrap();
        w.extend_from_slice(&secbuf_len.to_le_bytes());

        w.extend_from_slice(&self.previous_session_id.to_le_bytes());
        w.extend_from_slice(self.buffer);
    }
    fn size_hint(&self) -> usize {
        24 + self.buffer.len()
    }
    fn send_payload_size(&self) -> u32 {
        0
    }
    fn expected_response_payload_size(&self) -> u32 {
        0
    }
}

#[derive(Debug)]
struct SessionSetupResponse {
    flags: SessionFlags,
    sec_buffer: Box<[u8]>,
}
impl SessionSetupResponse {
    const STRUCTURE_SIZE: u16 = 9;
    fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, ReadError> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            return Err(ReadError::InvalidSize);
        }
        let flags = match r.read_u16_le()? {
            0x00 => SessionFlags::None,
            0x01 => SessionFlags::Guest,
            0x02 => SessionFlags::Anonymous,
            _ => return Err(ReadError::InvalidFlags),
        };
        let secbuf_offset = r.read_u16_le()?;
        let secbuf_length = r.read_u16_le()?;
        r.seek(SeekFrom::Start((secbuf_offset - 64) as u64))?;
        let mut sec_buffer = vec![0; secbuf_length as usize].into_boxed_slice();
        r.read_exact(&mut sec_buffer)?;
        Ok(Self { flags, sec_buffer })
    }
}

#[derive(Debug)]
enum ReadError {
    InvalidSize,
    InvalidFlags,
    Io(std::io::Error),
}
impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SessionFlags {
    None,
    Guest,
    Anonymous,
}

#[derive(Debug)]
struct LogoffRequest;
impl MessageBody for LogoffRequest {
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&4u32.to_le_bytes());
        w.extend_from_slice(&0u32.to_le_bytes());
    }
    fn size_hint(&self) -> usize {
        4
    }
    fn send_payload_size(&self) -> u32 {
        unreachable!()
    }
    fn expected_response_payload_size(&self) -> u32 {
        unreachable!()
    }
    fn calculate_credits(&self) -> u16 {
        1
    }
}
