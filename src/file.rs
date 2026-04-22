use std::{
    io::{Cursor, SeekFrom},
    num::NonZero,
    ops::BitOr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::{
    attributes::FileAttributes,
    error::{ErrorResponse2, ServerError},
    file::{
        close::{CloseRequest, CloseResponse, ReadCloseError},
        create::{CreateResponse, FileCreateRequest},
        read::{ReadFileError, ReadRequest, ReadResponse, ReadResponseError},
        server_copy::{ServerCopyError, ServerCopyResponse},
    },
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    ioctl::SourceKey,
    message::WriteError,
    tree::TreeConnection,
};

pub use create::CreateDisposition;

pub(crate) mod close;
pub(crate) mod create;
mod read;
mod resume_key;
pub mod server_copy;

type ReadFuture = Pin<Box<dyn Future<Output = Result<Box<[u8]>, ReadFileError>> + Sync + Send + 'static>>;
pub struct File {
    tree_connection: Arc<TreeConnection>,
    id: FileId,
    oplock_level: Option<OplockLevel202>,
    offset: u64,
    allocation_size: u64,
    end_of_file: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    future: Option<ReadFuture>,
}
impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHandle")
            .field("tree_connection", &self.tree_connection)
            .field("id", &self.id)
            .field("oplock_level", &self.oplock_level)
            .field("offset", &self.offset)
            .field("allocation_size", &self.allocation_size)
            .field("end_of_file", &self.end_of_file)
            .field("creation_time", &self.creation_time)
            .field("last_access_time", &self.last_access_time)
            .field("last_write_time", &self.last_write_time)
            .field("change_time", &self.change_time)
            .finish()
    }
}

impl File {
    pub(crate) async fn new(
        tree_connection: &Arc<TreeConnection>,
        path: &str,
        create_disposition: CreateDisposition,
    ) -> Result<File, OpenError> {
        let header = SyncHeader202Outgoing::from_tree_con(tree_connection, Command202::Create);
        let request_body = FileCreateRequest {
            oplock_level: None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: AccessMask::READ_DATA
                | AccessMask::WRITE_DATA
                | AccessMask::READ_ATTRIBUTES
                | AccessMask::READ_EA
                | AccessMask::READ_CONTROL,
            file_attributes: FileAttributes::EMPTY,
            create_options: 0x40 | 0x200,
            share_access: ShareAccess::SHARE_READ | ShareAccess::SHARE_WRITE,
            create_disposition,
            path,
        };
        let session = tree_connection.session();
        let key = session.requires_signing().then_some(session.session_key()).copied();

        let (header, body) = session
            .connection
            .signup_message(header, &request_body, false, key)
            .await
            .map_err(|e| match e {
                WriteError::Connection(error) => OpenError::Io(error),
                WriteError::MessageTooLong => OpenError::InvalidMessage,
            })?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &body));
        }
        verify_create_header(&header)?;
        let CreateResponse {
            oplock_level,
            create_action,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            attributes,
            id,
        } = CreateResponse::read_from(&mut body.as_ref()).unwrap();
        if attributes.contains(FileAttributes::DIRECTORY) {
            return Err(OpenError::IsADirectory);
        }
        Ok(File {
            oplock_level,
            offset: 0,
            tree_connection: tree_connection.clone(),
            id,
            allocation_size,
            end_of_file,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            future: None,
        })
    }
    pub fn length(&self) -> u64 {
        self.end_of_file
    }
    pub async fn read_raw(
        tree_connection: Arc<TreeConnection>,
        id: FileId,
        offset: u64,
        length: u32,
        minimum_count: u32,
    ) -> Result<Box<[u8]>, ReadFileError> {
        let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Read);
        let session = tree_connection.session();
        let key = session.requires_signing().then_some(session.session_key()).copied();
        let req = ReadRequest {
            length,
            offset,
            id,
            minimum_count,
        };
        let (header, body) = session
            .connection
            .signup_message(header, &req, true, key)
            .await
            .map_err(|w| match w {
                WriteError::Connection(error) => ReadFileError::Io(error),
                WriteError::MessageTooLong => ReadFileError::InvalidMessage,
            })?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &body));
        }
        verify_read_header(&header)?;
        match ReadResponse::read_from(Cursor::new(body)) {
            Ok(ok) => Ok(ok.into_inner()),
            Err(ReadResponseError::Io(io)) => Err(ReadFileError::Io(io)),
            Err(ReadResponseError::InvalidMessage) => Err(ReadFileError::InvalidMessage),
        }
    }
    async fn send_close(&mut self) -> Result<(), std::io::Error> {
        Self::send_close_raw(self.tree_connection.clone(), self.id).await
    }
    async fn send_close_raw(tree_connection: Arc<TreeConnection>, id: FileId) -> Result<(), std::io::Error> {
        let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Close);
        let session = tree_connection.session();
        let session_key = session.requires_signing().then_some(session.session_key()).copied();
        let (header, body) = match session
            .connection
            .signup_message(header, &CloseRequest { id }, false, session_key)
            .await
        {
            Ok(t) => t,
            Err(WriteError::Connection(io)) => return Err(io),
            Err(WriteError::MessageTooLong) => unreachable!(),
        };
        if let Some(code) = NonZero::new(header.status) {
            panic!("Error with code {code}");
        }
        let _ = verify_close_header(&header);
        let _body = CloseResponse::read_from(&mut body.as_ref());
        Ok(())
    }
    pub async fn close(mut self) -> Result<(), std::io::Error> {
        self.send_close().await
    }
    pub async fn get_resume_key(&self) -> SourceKey {
        resume_key::get_resume_key(self).await
    }
    pub async fn copy_to<R: server_copy::FileRange>(
        &self,
        to: &Self,
        chunks: &[server_copy::Chunk<R>],
    ) -> Result<ServerCopyResponse, ServerCopyError> {
        server_copy::server_copy(self, to, chunks).await
    }
}
impl AsyncRead for File {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let until_end = self.end_of_file.saturating_sub(self.offset);
        if until_end == 0 {
            return Poll::Ready(Ok(()));
        }
        let max_protocol = self.tree_connection.session().connection.max_read_size() as u64;
        let max_wanted = buf.remaining() as u64;
        let to_request = until_end.min(max_protocol).min(max_wanted) as u32;
        if to_request == 0 {
            return Poll::Ready(Ok(()));
        }
        let tree = self.tree_connection.clone();
        let id = self.id;
        let offset = self.offset;
        let fut = self.future.get_or_insert_with(|| {
            let fut = async move { Self::read_raw(tree, id, offset, to_request, 0).await };
            Box::pin(fut)
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => {
                self.future = None;
                match res {
                    Ok(outbuf) => {
                        assert!(outbuf.len() <= to_request as usize);
                        let read_len = outbuf.len() as u64;
                        self.offset += read_len;
                        buf.put_slice(&outbuf);
                        Poll::Ready(Ok(()))
                    }
                    Err(rd) => Poll::Ready(Err(rd.collapse_to_io_error())),
                }
            }
        }
    }
}
impl AsyncSeek for File {
    fn start_seek(mut self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        let new = match pos {
            SeekFrom::Start(s) => s,
            SeekFrom::Current(c) => self.offset.saturating_add_signed(c),
            SeekFrom::End(c) => self.end_of_file.saturating_add_signed(c),
        };
        self.offset = new;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.offset))
    }
}

fn verify_create_header(header: &SyncHeader202Incoming) -> Result<(), OpenError> {
    if header.command != Command202::Create || header.is_async() {
        Err(OpenError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn verify_read_header(header: &SyncHeader202Incoming) -> Result<(), ReadFileError> {
    if header.command != Command202::Read || header.is_async() {
        Err(ReadFileError::InvalidMessage)
    } else {
        Ok(())
    }
}

pub(crate) fn verify_close_header(header: &SyncHeader202Incoming) -> Result<(), ReadCloseError> {
    if header.command != Command202::Close || header.is_async() {
        Err(ReadCloseError::InvalidHeader)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum OpenError {
    IsADirectory,
    Io(std::io::Error),
    InvalidMessage,
    ServerError { code: NonZero<u32>, body: ErrorResponse2 },
}
impl From<std::io::Error> for OpenError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl ServerError for OpenError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }

    fn parsed(code: NonZero<u32>, body: crate::error::ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OplockLevel202 {
    II,
    Exclusive,
    Batch,
}

#[derive(Clone, Copy, Debug)]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegate,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AccessMask(u32);
impl AccessMask {
    pub(crate) const READ_DATA: Self = Self(0x01);
    pub(crate) const WRITE_DATA: Self = Self(0x02);
    pub(crate) const APPEND_DATA: Self = Self(0x04);
    pub(crate) const READ_EA: Self = Self(0x08);
    pub(crate) const WRITE_EA: Self = Self(0x10);
    pub(crate) const DELETE_CHILD: Self = Self(0x40);
    pub(crate) const EXECUTE: Self = Self(0x20);
    pub(crate) const READ_ATTRIBUTES: Self = Self(0x80);
    pub(crate) const WRITE_ATTRIBUTES: Self = Self(0x100);
    pub(crate) const DELETE: Self = Self(0x10000);
    pub(crate) const READ_CONTROL: Self = Self(0x20000);
    pub(crate) const WRITE_DAC: Self = Self(0x40000);
    pub(crate) const WRITE_OWNER: Self = Self(0x80000);
    pub(crate) const SYNCHRONIZE: Self = Self(0x100000);
    pub(crate) const ACCESS_SYSTEM_SECURITY: Self = Self(0x1000000);
    pub(crate) const MAXIMUM_ALLOWED: Self = Self(0x2000000);
    pub(crate) const GENERIC_ALL: Self = Self(0x10000000);
    pub(crate) const GENERIC_EXECUTE: Self = Self(0x20000000);
    pub(crate) const GENERIC_WRITE: Self = Self(0x40000000);
    pub(crate) const GENERIC_READ: Self = Self(0x80000000);

    pub fn empty() -> Self {
        Self::default()
    }
}
impl BitOr for AccessMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ShareAccess(u32);
impl ShareAccess {
    pub(crate) const SHARE_READ: Self = Self(0x01);
    pub(crate) const SHARE_WRITE: Self = Self(0x02);
    pub(crate) const SHARE_DELETE: Self = Self(0x04);
    fn empty() -> Self {
        Self::default()
    }
}
impl BitOr for ShareAccess {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FileId {
    pub(crate) persistent: [u8; 8],
    pub(crate) volatile: [u8; 8],
}
impl From<[u8; 16]> for FileId {
    fn from(value: [u8; 16]) -> Self {
        let persistent = *value.first_chunk().unwrap();
        let volatile = *value.last_chunk().unwrap();
        Self { persistent, volatile }
    }
}
