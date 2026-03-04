use std::{
    borrow::Borrow,
    io::{Cursor, Read, Seek, Write},
    marker::PhantomData,
    net::TcpStream,
    num::NonZero,
    ops::DerefMut,
};

use crate::{
    ReadLe,
    client::{Client202, Connection},
    error::{ErrorResponse2, ServerError},
    file::{FileHandle, OpenError},
    header::{Command202, SyncHeader202Outgoing},
    message::{
        MessageBody, Validation, WriteError as MsgWriteError, read_202_message, write_202_message,
    },
    session::Session202,
    share_name::{InvalidShareName, ShareName},
    sync::Access,
};

#[derive(Debug)]
pub struct TreeConnection<
    Session: Borrow<Session202<Con, Stream, Client>>,
    Con: Borrow<Connection<Client, Stream>>,
    Stream: Access<TcpStream>,
    Client,
> {
    session: Session,
    share_type: ShareType,
    /// There are no valid flags in 202 besides the SMB2_SHARE_CAP_DFS
    dfs_capability: bool,
    id: u32,
    _marker: PhantomData<(Con, Stream, Client)>,
}
impl<
    Session: Borrow<Session202<Con, Stream, Client>>,
    Con: Borrow<Connection<Client, Stream>>,
    Stream: Access<TcpStream>,
    Client: Borrow<Client202>,
> TreeConnection<Session, Con, Stream, Client>
{
    pub fn new(
        session: Session,
        path: &str,
    ) -> Result<TreeConnection<Session, Con, Stream, Client>, TreeConnectError> {
        let tc_header = SyncHeader202Outgoing::from_session::<_, _, _>(
            session.borrow(),
            Command202::TreeConnect,
        );
        let session_key = session
            .borrow()
            .requires_signing()
            .then_some(session.borrow().session_key())
            .copied();
        if let Err(e) = parse_share_path(path) {
            return Err(TreeConnectError::InvalidPath(e));
        };
        let mut lock = session.borrow().connection.borrow().borrow_tcp();
        write_202_message(
            lock.deref_mut(),
            session_key,
            tc_header,
            &TreeConnectRequest(path),
            false,
        )?;
        let (header, msg) =
            read_202_message(lock.deref_mut(), Validation::from(session_key)).unwrap();
        drop(lock);
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
            _marker: PhantomData,
        })
    }
    pub fn disconnect(self) {
        drop(self)
    }
}
impl<
    Session: Borrow<Session202<Con, Stream, Client>>,
    Con: Borrow<Connection<Client, Stream>>,
    Stream: Access<TcpStream>,
    Client,
> TreeConnection<Session, Con, Stream, Client>
{
    pub(crate) fn session(&self) -> &Session202<Con, Stream, Client> {
        self.session.borrow()
    }
    pub fn id(&self) -> u32 {
        self.id
    }
}
impl<
    Session: Borrow<Session202<Con, Stream, Client>>,
    Con: Borrow<Connection<Client, Stream>>,
    Stream: Access<TcpStream>,
    Client,
> TreeConnection<Session, Con, Stream, Client>
{
    pub fn open_file<'tree>(
        &'tree self,
        path: &str,
    ) -> Result<FileHandle<'tree, Session, Con, Stream, Client>, OpenError> {
        FileHandle::new(self, path)
    }
}
impl<
    Session: Borrow<Session202<Con, Stream, Client>>,
    Con: Borrow<Connection<Client, Stream>>,
    Stream: Access<TcpStream>,
    Client,
> Drop for TreeConnection<Session, Con, Stream, Client>
{
    fn drop(&mut self) {
        let header = SyncHeader202Outgoing::from_tree_con(self, Command202::TreeDisconnect);
        let session = self.session.borrow();
        let key = session.requires_signing().then_some(*session.session_key());
        let mut lock = session.connection.borrow().borrow_tcp();
        let _ = write_202_message(lock.deref_mut(), key, header, &TreeDisconnectRequest, false);
        let Ok((_header, body)) = read_202_message(lock.deref_mut(), Validation::from(key)) else {
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
        let utf16 = crate::to_wide(self.0);
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
