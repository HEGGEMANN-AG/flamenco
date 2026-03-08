use std::{
    fmt::Debug,
    io::{Cursor, SeekFrom},
    num::NonZero,
    sync::Arc,
};

use kenobi::{
    client::{ClientBuilder, StepOut},
    cred::{Credentials, Outbound},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    client::{Connection, GuestPolicy},
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing},
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
        cred: &Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Arc<Session202>, SessionSetupError> {
        let mut auth_context = match ClientBuilder::new_from_credentials(cred, target_spn)
            .request_delegation()
            .initialize()
        {
            StepOut::Pending(pending) => pending,
            StepOut::Finished(_c) => unreachable!(),
        };
        let mut session_id = None;
        loop {
            let client = &connection.client;
            let header = SyncHeader202Outgoing {
                command: Command202::SessionSetup,
                credits: 0,
                flags: 0,
                next_command: None,
                message_id: 0,
                tree_id: 0,
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
            let (header, body) = connection
                .signup_message(header, &body, false, None)
                .await?;
            // Lookup session ID
            if let Some(code) = NonZero::new(header.status)
                && code.get() != ERROR_MORE_PROCESSING_REQUIRED
            {
                return Err(SessionSetupError::handle_error_body(code, &body));
            }
            let SessionSetupResponse { flags, sec_buffer } =
                SessionSetupResponse::read_from(Cursor::new(body)).await?;

            auth_context = match auth_context.step(&sec_buffer) {
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
                        SessionFlags::None => {
                            connection.server_requires_signing() || client.requires_signing
                        }
                        SessionFlags::Guest => client.requires_signing,
                        SessionFlags::Anonymous => false,
                    };
                    let Some(id) = NonZero::new(header.session_id) else {
                        return Err(SessionSetupError::InvalidMessage);
                    };
                    let session = Session202 {
                        flags,
                        requires_signing,
                        id,
                        session_key,
                        connection: connection.clone(),
                    };
                    let as_arc = Arc::new(session);
                    connection
                        .signup_session(id, Arc::downgrade(&as_arc))
                        .await
                        .unwrap();
                    return Ok(as_arc);
                }
            };
            session_id = NonZero::new(header.session_id);
        }
    }
    pub async fn tree_connect(
        self: Arc<Self>,
        share_path: &str,
    ) -> Result<Arc<TreeConnection>, TreeConnectError> {
        TreeConnection::new(self, share_path).await
    }
    pub async fn logoff(self) {
        let logoff_header = SyncHeader202Outgoing {
            command: Command202::Logoff,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: 0,
            tree_id: 0,
            session_id: Some(self.id),
        };
        let key = self.requires_signing().then_some(self.session_key);
        self.connection.remove_session(self.id).await;
        let _ = self
            .connection
            .signup_message(logoff_header, &LogoffRequest, false, key)
            .await;
    }
}

#[derive(Debug)]
pub enum SessionSetupError {
    Io(std::io::Error),
    DisallowedGuestAccess,
    AuthContextTokenTooLong,
    SessionKeyTooShort,
    InvalidMessage,
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl From<MsgWriteError> for SessionSetupError {
    fn from(value: MsgWriteError) -> Self {
        match value {
            MsgWriteError::Connection(error) => Self::Io(error),
            MsgWriteError::MessageTooLong => Self::AuthContextTokenTooLong,
        }
    }
}
impl From<MsgReadError> for SessionSetupError {
    fn from(value: MsgReadError) -> Self {
        match value {
            MsgReadError::InvalidSignature
            | MsgReadError::InvalidlySignedMessage
            | MsgReadError::NotSigned
            | MsgReadError::NetBIOS => Self::InvalidMessage,
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
impl SessionSetupRequest<'_> {
    async fn write_into<W: AsyncWriteExt + Unpin>(&self, w: &mut W) -> Result<(), WriteError> {
        w.write_all(&25u16.to_le_bytes()).await?;
        // flags
        w.write_all(&[0]).await?;
        // security mode
        w.write_all(&[self.security_mode.to_value()]).await?;
        w.write_all(&self.capabilities.to_le_bytes()).await?;
        // channel
        w.write_all(&0u32.to_le_bytes()).await?;

        let secbuf_offset: u16 = 64 + 24;
        w.write_all(&secbuf_offset.to_le_bytes()).await?;
        let Ok(secbuf_len): Result<u16, _> = self.buffer.len().try_into() else {
            return Err(WriteError::BufferTooLong);
        };
        w.write_all(&secbuf_len.to_le_bytes()).await?;

        w.write_all(&self.previous_session_id.to_le_bytes()).await?;
        w.write_all(self.buffer).await?;
        Ok(())
    }
}
impl MessageBody for SessionSetupRequest<'_> {
    type Err = WriteError;
    async fn write_to<W: AsyncWriteExt + Unpin>(&self, w: &mut W) -> Result<(), Self::Err> {
        SessionSetupRequest::write_into(self, w).await
    }
    fn size_hint(&self) -> usize {
        24 + self.buffer.len()
    }
}

#[derive(Debug)]
enum WriteError {
    Io(std::io::Error),
    BufferTooLong,
}

impl From<std::io::Error> for WriteError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
struct SessionSetupResponse {
    flags: SessionFlags,
    sec_buffer: Box<[u8]>,
}
impl SessionSetupResponse {
    const STRUCTURE_SIZE: u16 = 9;
    async fn read_from<R: AsyncReadExt + AsyncSeekExt + Unpin>(
        mut r: R,
    ) -> Result<Self, ReadError> {
        if r.read_u16_le().await? != Self::STRUCTURE_SIZE {
            return Err(ReadError::InvalidSize);
        }
        let flags = match r.read_u16_le().await? {
            0x00 => SessionFlags::None,
            0x01 => SessionFlags::Guest,
            0x02 => SessionFlags::Anonymous,
            _ => return Err(ReadError::InvalidFlags),
        };
        let secbuf_offset = r.read_u16_le().await?;
        let secbuf_length = r.read_u16_le().await?;
        r.seek(SeekFrom::Start((secbuf_offset - 64) as u64)).await?;
        let mut sec_buffer = vec![0; secbuf_length as usize].into_boxed_slice();
        r.read_exact(&mut sec_buffer).await?;
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
    type Err = std::io::Error;
    async fn write_to<W: AsyncWriteExt + Unpin>(&self, w: &mut W) -> Result<(), Self::Err> {
        w.write_all(&4u32.to_le_bytes()).await?;
        w.write_all(&0u32.to_le_bytes()).await?;
        Ok(())
    }
    fn size_hint(&self) -> usize {
        4
    }
}
