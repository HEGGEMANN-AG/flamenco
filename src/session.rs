use std::{
    io::{Cursor, ErrorKind, Read, Seek, SeekFrom, Write},
    num::NonZero,
};

use kenobi::{
    client::{ClientBuilder, StepOut},
    cred::{Credentials, Outbound},
};

use crate::{
    ReadLe,
    client::{Connection, GuestPolicy},
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing},
    message::{
        MessageBody, ReadError as MsgReadError, Validation, WriteError as MsgWriteError,
        read_202_message, write_202_message,
    },
    sign::SecurityMode,
    tree::{TreeConnectError, TreeConnection},
};

const ERROR_MORE_PROCESSING_REQUIRED: u32 = 0xC0000016;

pub struct Session202<'con, 'cred> {
    cred: &'cred Credentials<Outbound>,
    session_key: [u8; 16],
    pub(crate) id: u64,
    pub(crate) connection: &'con mut Connection<'con>,
    flags: SessionFlags,
}
impl Session202<'_, '_> {
    pub fn requires_signing(&self) -> bool {
        let con = &self.connection;
        match self.flags {
            SessionFlags::None => con.server_requires_signing() || con.client.requires_signing,
            SessionFlags::Guest => con.client.requires_signing,
            SessionFlags::Anonymous => false,
        }
    }
    pub(crate) fn new<'con, 'cred>(
        connection: &'con mut Connection<'con>,
        cred: &'cred Credentials<Outbound>,
        target_spn: Option<&str>,
    ) -> Result<Session202<'con, 'cred>, SessionSetupError> {
        let mut auth_context = match ClientBuilder::new_from_credentials(cred, target_spn)
            .request_delegation()
            .initialize()
        {
            StepOut::Pending(pending) => pending,
            StepOut::Finished(_c) => unreachable!(),
        };
        let mut session_id = 0;
        loop {
            let message_id = connection.fetch_increment_message_id();
            let header = SyncHeader202Outgoing {
                command: Command202::SessionSetup,
                credits: 256,
                flags: 0,
                next_command: None,
                message_id,
                tree_id: 0,
                session_id,
            };
            let body = SessionSetupRequest {
                security_mode: if connection.client.requires_signing {
                    SecurityMode::SigningRequired
                } else {
                    SecurityMode::SigningEnabled
                },
                capabilities: 0,
                previous_session_id: 0,
                buffer: auth_context.next_token(),
            };
            write_202_message(&mut connection.tcp, None, header, &body)?;
            let message_buffer = buffer_for_delayed_validation(&mut connection.tcp)?;
            let (header, body) = read_202_message(&mut message_buffer.as_ref(), Validation::Skip)?;
            // Lookup session ID
            if let Some(code) = NonZero::new(header.status)
                && code.get() != ERROR_MORE_PROCESSING_REQUIRED
            {
                return Err(SessionSetupError::handle_error_body(code, &body));
            }
            let SessionSetupResponse { flags, sec_buffer } =
                SessionSetupResponse::read_from(Cursor::new(body))?;

            auth_context = match auth_context.step(&sec_buffer) {
                StepOut::Pending(p) => p,
                StepOut::Finished(context) => {
                    let session_key = *context
                        .session_key()
                        .first_chunk::<16>()
                        .ok_or(SessionSetupError::SessionKeyTooShort)?;
                    let (_, _) = read_202_message(&*message_buffer, Validation::Key(session_key))?;
                    if flags == SessionFlags::Guest {
                        match connection.client.guest_policy {
                            GuestPolicy::Disallowed => {
                                return Err(SessionSetupError::DisallowedGuestAccess);
                            }
                            GuestPolicy::AllowedInsecurely
                                if connection.client.requires_signing =>
                            {
                                return Err(SessionSetupError::DisallowedGuestAccess);
                            }
                            _ => {}
                        }
                    }
                    return Ok(Session202 {
                        flags,
                        cred,
                        id: header.session_id,
                        session_key,
                        connection,
                    });
                }
            };
            session_id = header.session_id;
        }
    }
    pub(crate) fn session_key(&self) -> &[u8; 16] {
        &self.session_key
    }
    pub fn close(self) {
        drop(self);
    }
}
impl<'con, 'cred> Session202<'con, 'cred> {
    pub fn tree_connect<'session>(
        &'session mut self,
        share_path: &str,
    ) -> Result<TreeConnection<'session, 'con, 'cred>, TreeConnectError> {
        TreeConnection::new(self, share_path)
    }
}
impl<'con, 'cred> Drop for Session202<'con, 'cred> {
    fn drop(&mut self) {
        let logoff_header = SyncHeader202Outgoing {
            command: Command202::Logoff,
            credits: 0,
            flags: 0,
            next_command: None,
            message_id: self.connection.fetch_increment_message_id(),
            tree_id: 0,
            session_id: self.id,
        };
        let key = self.requires_signing().then_some(self.session_key);
        let _ = write_202_message(&mut self.connection.tcp, key, logoff_header, &LogoffRequest);
        let _ = read_202_message(&mut self.connection.tcp, Validation::Key(self.session_key));
    }
}

fn buffer_for_delayed_validation<R: Read>(mut r: R) -> Result<Box<[u8]>, MsgReadError> {
    let mut bios_size = [0u8; 4];
    r.read_exact(&mut bios_size)
        .map_err(MsgReadError::Connection)?;
    let message_size = match u32::from_be_bytes(bios_size) {
        0..64 => {
            return Err(MsgReadError::Connection(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "Not enough data for header",
            )));
        }
        0x0100_0000.. => return Err(MsgReadError::NetBIOS),
        size => size,
    };
    let message_body_size = message_size as usize;
    let mut message_body_with_netbios = vec![0u8; message_body_size + 4].into_boxed_slice();
    let (bios, body) = message_body_with_netbios
        .split_first_chunk_mut::<4>()
        .unwrap();
    bios.copy_from_slice(&bios_size);
    r.read_exact(body).map_err(MsgReadError::Connection)?;
    Ok(message_body_with_netbios)
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
    fn io(io: std::io::Error) -> Self {
        Self::Io(io)
    }
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
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
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), WriteError> {
        w.write_all(&25u16.to_le_bytes())?;
        // flags
        w.write_all(&[0])?;
        // security mode
        w.write_all(&[self.security_mode.to_value()])?;
        w.write_all(&self.capabilities.to_le_bytes())?;
        // channel
        w.write_all(&0u32.to_le_bytes())?;

        let secbuf_offset: u16 = 64 + 24;
        w.write_all(&secbuf_offset.to_le_bytes())?;
        let Ok(secbuf_len): Result<u16, _> = self.buffer.len().try_into() else {
            return Err(WriteError::BufferTooLong);
        };
        w.write_all(&secbuf_len.to_le_bytes())?;

        w.write_all(&self.previous_session_id.to_le_bytes())?;
        w.write_all(self.buffer)?;
        Ok(())
    }
}
impl MessageBody for SessionSetupRequest<'_> {
    type Err = WriteError;
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        SessionSetupRequest::write_into(self, w)
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
    fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, ReadError> {
        if r.read_u16()? != Self::STRUCTURE_SIZE {
            return Err(ReadError::InvalidSize);
        }
        let flags = match r.read_u16()? {
            0x00 => SessionFlags::None,
            0x01 => SessionFlags::Guest,
            0x02 => SessionFlags::Anonymous,
            _ => return Err(ReadError::InvalidFlags),
        };
        let secbuf_offset = r.read_u16()?;
        let secbuf_length = r.read_u16()?;
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
    type Err = std::io::Error;
    fn write_to<W: Write>(&self, mut w: W) -> Result<(), Self::Err> {
        w.write_all(&4u32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        Ok(())
    }
    fn size_hint(&self) -> usize {
        4
    }
}
