use std::{
    borrow::Borrow,
    io::{Cursor, Read, Seek, SeekFrom},
    num::NonZero,
    sync::Arc,
};

use crate::{
    ReadIntLe,
    dir::CreateDirError,
    error::{ErrorResponse2, ServerError},
    file::{File, OpenError, create::CreateDisposition},
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError as MsgReadError, WriteError as MsgWriteError},
    session::Session202,
    share_name::{InvalidShareName, ShareName},
};

#[derive(Debug)]
pub struct TreeConnection {
    session: Arc<Session202>,
    share_type: ShareType,
    /// There are no valid flags in 202 besides the SMB2_SHARE_CAP_DFS
    dfs_capability: bool,
    id: NonZero<u32>,
}
impl TreeConnection {
    pub async fn new(session: Arc<Session202>, path: &str) -> Result<Arc<TreeConnection>, TreeConnectError> {
        let tc_header = SyncHeader202Outgoing::from_session(&session, Command202::TreeConnect);
        let session_key = session.requires_signing().then_some(session.session_key()).copied();
        if let Err(e) = parse_share_path(path) {
            return Err(TreeConnectError::InvalidPath(e));
        };
        let (header, msg) = session
            .connection
            .signup_message(tc_header, &TreeConnectRequest(path), false, session_key)
            .await?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &msg));
        }
        verify_tree_connect_header(&header)?;
        let response = TreeConnectResponse::read_from(&mut Cursor::new(msg))?;
        let Some(id) = header.tree_id else {
            return Err(TreeConnectError::InvalidMessage);
        };
        let tree = TreeConnection {
            session,
            share_type: response.share_type,
            // Ignore all other capabilities for now (since it's 202)
            dfs_capability: response.capabilities & 0x08 != 0,
            id,
        };
        Ok(Arc::new(tree))
    }
    pub async fn disconnect(self) {
        let session = self.session.clone();
        let key = session.requires_signing().then_some(*session.session_key());
        let header = SyncHeader202Outgoing::from_tree_con(&self, Command202::TreeDisconnect);
        let Ok((header, body)) = session
            .connection
            .signup_message(header, &TreeDisconnectRequest, false, key)
            .await
        else {
            return;
        };
        let Ok(_) = TreeDisconnectResponse::read_from(&mut body.as_ref()) else {
            return;
        };
        let _ = verify_tree_disconnect_header(&header);
    }
    pub(crate) fn session(&self) -> &Session202 {
        self.session.borrow()
    }
    pub fn id(&self) -> NonZero<u32> {
        self.id
    }
    pub async fn open_file(
        self: Arc<Self>,
        path: &str,
        create_disposition: CreateDisposition,
    ) -> Result<File, OpenError> {
        File::new(self, path, create_disposition).await
    }
    pub async fn create_dir(self: Arc<Self>, path: &str) -> Result<(), CreateDirError> {
        crate::dir::create_dir(self, path, crate::dir::DirCreateDisposition::Create).await
    }
}

fn verify_tree_connect_header(header: &SyncHeader202Incoming) -> Result<(), TreeConnectError> {
    if header.command != Command202::TreeConnect || header.is_async() {
        return Err(TreeConnectError::InvalidMessage);
    }
    Ok(())
}

fn verify_tree_disconnect_header(header: &SyncHeader202Incoming) -> Result<(), TreeDisconnectError> {
    if header.command != Command202::TreeDisconnect || header.is_async() {
        Err(TreeDisconnectError::InvalidMessage)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum TreeConnectError {
    Io(std::io::Error),
    InvalidPath(InvalidSharePath),
    InvalidMessage,
    Server { code: NonZero<u32>, body: ErrorResponse2 },
}
impl ServerError for TreeConnectError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
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
impl From<MsgReadError> for TreeConnectError {
    fn from(value: MsgReadError) -> Self {
        match value {
            MsgReadError::InvalidNetbiosLength | MsgReadError::InvalidlySignedMessage => Self::InvalidMessage,
            MsgReadError::Connection(error) => Self::Io(error),
        }
    }
}
impl From<std::io::Error> for TreeConnectError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
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

#[derive(Debug)]
enum TreeDisconnectError {
    InvalidMessage,
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
}
impl MessageBody for TreeConnectRequest<'_> {
    fn size_hint(&self) -> usize {
        8 + (self.0.len() * 2)
    }
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&Self::STRUCTURE_SIZE.to_le_bytes());
        w.extend_from_slice(&0u16.to_le_bytes());
        let utf16 = crate::to_wide(self.0);
        w.extend_from_slice(&(64 + 8u16).to_le_bytes());
        w.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        w.extend_from_slice(&utf16);
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
    fn read_from<R: Read + Seek>(r: &mut R) -> Result<Self, ReadError> {
        if r.read_u16_le()? != 16 {
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
        r.seek(SeekFrom::Current(1))?;
        let flags = r.read_u32_le()?;
        // Todo cache check
        let capabilities = r.read_u32_le()?;
        let maximal_access = r.read_u32_le()?;
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
impl MessageBody for TreeDisconnectRequest {
    fn size_hint(&self) -> usize {
        8
    }
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&4u16.to_le_bytes());
        w.extend_from_slice(&0u16.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug)]
struct TreeDisconnectResponse;
impl TreeDisconnectResponse {
    fn read_from<R: Read>(r: &mut R) -> Result<Self, ReadDisconnectError> {
        if r.read_u16_le()? != 4 {
            return Err(ReadDisconnectError::InvalidSize);
        };
        let _ignored = r.read_u16_le()?;
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
