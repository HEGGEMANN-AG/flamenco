use std::{
    io::{Cursor, Read, Seek, Write},
    num::NonZero,
};

use crate::{
    ReadLe,
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing},
    message::{
        MessageBody, Validation, WriteError as MsgWriteError, read_202_message, write_202_message,
    },
    session::Session202,
    share_name::{InvalidShareName, ShareName},
};

#[derive(Debug)]
pub struct TreeConnection<'session, 'con, 'cred> {
    session: &'session mut Session202<'con, 'cred>,
    share_type: ShareType,
    /// There are no valid flags in 202 besides the SMB2_SHARE_CAP_DFS
    dfs_capability: bool,
    id: u32,
}
impl TreeConnection<'_, '_, '_> {
    pub fn new<'session, 'con, 'cred>(
        session: &'session mut Session202<'con, 'cred>,
        path: &str,
    ) -> Result<TreeConnection<'session, 'con, 'cred>, TreeConnectError> {
        let tc_header = SyncHeader202Outgoing::from_session(session, Command202::TreeConnect);
        let session_key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
        if let Err(e) = parse_share_path(path) {
            return Err(TreeConnectError::InvalidPath(e));
        };
        write_202_message(
            &mut session.connection.tcp,
            session_key,
            tc_header,
            &TreeConnectRequest(path),
        )?;
        let (header, msg) =
            read_202_message(&mut session.connection.tcp, Validation::from(session_key)).unwrap();
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &msg));
        }
        let response = TreeConnectResponse::read_from(Cursor::new(msg))?;
        Ok(TreeConnection {
            session,
            share_type: response.share_type,
            // Ignore all other capabilities for now (since it's 202)
            dfs_capability: response.capabilities & 0x08 != 0,
            id: header.tree_id,
        })
    }
    pub fn disconnect(self) {
        drop(self)
    }
}
impl<'session, 'con, 'cred> TreeConnection<'session, 'con, 'cred> {
    pub(crate) fn session_mut(&mut self) -> &mut Session202<'con, 'cred> {
        self.session
    }
    pub fn id(&self) -> u32 {
        self.id
    }
}
impl Drop for TreeConnection<'_, '_, '_> {
    fn drop(&mut self) {
        let header = SyncHeader202Outgoing::from_tree_con(self, Command202::TreeDisconnect);
        let session = &mut self.session;
        let key = session.requires_signing().then_some(*session.session_key());
        let _ = write_202_message(
            &mut session.connection.tcp,
            key,
            header,
            &TreeDisconnectRequest,
        );
        let Ok((_header, body)) =
            read_202_message(&mut session.connection.tcp, Validation::from(key))
        else {
            return;
        };
        let _ = TreeDisconnectResponse::read_from(body.as_ref());
    }
}

#[derive(Debug)]
pub enum TreeConnectError {
    Io(std::io::Error),
    InvalidPath(InvalidSharePath),
    InvalidMessage,
    Server {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl ServerError for TreeConnectError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
    fn io(io: std::io::Error) -> Self {
        Self::Io(io)
    }
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::Server { code, body }
    }
}
impl From<MsgWriteError> for TreeConnectError {
    fn from(value: MsgWriteError) -> Self {
        match value {
            MsgWriteError::Connection(io) => Self::Io(io),
            MsgWriteError::MessageTooLong => unreachable!("share path limit already enforces this"),
        }
    }
}
impl From<ReadError> for TreeConnectError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::Io(io) => Self::Io(io),
            ReadError::InvalidSize | ReadError::InvalidShareType => Self::InvalidMessage,
        }
    }
}

fn parse_share_path(s: &str) -> Result<(&str, ShareName), InvalidSharePath> {
    let Some(without_double_slashes) = s.strip_prefix(r"\\") else {
        return Err(InvalidSharePath::NoLeadingSlashes);
    };
    let Some((server_name, share_name)) = without_double_slashes.split_once('\\') else {
        return Err(InvalidSharePath::MissingSeparator);
    };
    if server_name.chars().count() > 255 {
        return Err(InvalidSharePath::ServerNameTooLong);
    };
    let share_name = ShareName::new(share_name).map_err(InvalidSharePath::InvalidShareName)?;
    Ok((server_name, share_name))
}
#[derive(Debug)]
pub enum InvalidSharePath {
    NoLeadingSlashes,
    MissingSeparator,
    ServerNameTooLong,
    InvalidShareName(InvalidShareName),
}

#[derive(Debug)]
struct TreeConnectRequest<'s>(&'s str);
impl TreeConnectRequest<'_> {
    const STRUCTURE_SIZE: u16 = 9;
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), WriteError> {
        w.write_all(&Self::STRUCTURE_SIZE.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        let utf16 = self
            .0
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>();
        w.write_all(&(64 + 8u16).to_le_bytes())?;
        w.write_all(&(utf16.len() as u16).to_le_bytes())?;
        w.write_all(&utf16)?;
        Ok(())
    }
}
impl MessageBody for TreeConnectRequest<'_> {
    type Err = WriteError;
    fn size_hint(&self) -> usize {
        8 + (self.0.len() * 2)
    }
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
}
impl From<std::io::Error> for WriteError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
struct TreeConnectResponse {
    share_type: ShareType,
    flags: u32,
    capabilities: u32,
    maximal_access: u32,
}
impl TreeConnectResponse {
    fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, ReadError> {
        if r.read_u16()? != 16 {
            return Err(ReadError::InvalidSize);
        }
        let mut share = 0;
        r.read_exact(std::slice::from_mut(&mut share))?;
        let share_type = match share {
            0x01 => ShareType::Disk,
            0x02 => ShareType::Pipe,
            0x03 => ShareType::Printer,
            _ => return Err(ReadError::InvalidShareType),
        };
        r.seek_relative(1)?;
        let flags = r.read_u32()?;
        // Todo cache check
        let capabilities = r.read_u32()?;
        let maximal_access = r.read_u32()?;
        Ok(Self {
            share_type,
            flags,
            capabilities,
            maximal_access,
        })
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    InvalidSize,
    InvalidShareType,
}
impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ShareType {
    Disk,
    Pipe,
    Printer,
}

#[derive(Clone, Copy, Debug)]
struct TreeDisconnectRequest;
impl TreeDisconnectRequest {
    fn write_into<W: Write>(self, mut w: W) -> Result<(), std::io::Error> {
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        Ok(())
    }
}
impl MessageBody for TreeDisconnectRequest {
    type Err = std::io::Error;
    fn size_hint(&self) -> usize {
        8
    }
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        (*self).write_into(w)
    }
}

#[derive(Clone, Copy, Debug)]
struct TreeDisconnectResponse;
impl TreeDisconnectResponse {
    fn read_from<R: Read>(mut r: R) -> Result<Self, ReadDisconnectError> {
        if r.read_u16()? != 4 {
            return Err(ReadDisconnectError::InvalidSize);
        };
        let _ignored = r.read_u16()?;
        Ok(Self)
    }
}
#[derive(Debug)]
enum ReadDisconnectError {
    Io(std::io::Error),
    InvalidSize,
}
impl From<std::io::Error> for ReadDisconnectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
