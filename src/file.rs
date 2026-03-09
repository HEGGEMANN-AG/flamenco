use std::{
    io::{Cursor, Read, SeekFrom},
    num::NonZero,
    ops::BitOr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::{
    ReadIntLe,
    error::{ErrorResponse2, ServerError},
    file::{
        close::{CloseRequest, CloseResponse, ReadCloseError},
        read::{ReadFileError, ReadRequest, ReadResponse, ReadResponseError},
    },
    header::{Command202, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, WriteError},
    tree::TreeConnection,
};

mod close;
mod read;

type ReadFuture = Pin<Box<dyn Future<Output = Result<Box<[u8]>, ReadFileError>> + Send + 'static>>;
pub struct FileHandle {
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
impl std::fmt::Debug for FileHandle {
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
impl FileHandle {
    pub(crate) async fn new(
        tree_connection: Arc<TreeConnection>,
        path: &str,
    ) -> Result<FileHandle, OpenError> {
        let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Create);
        let request_body = FileCreateRequest {
            oplock_level: None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: AccessMask::READ_DATA
                | AccessMask::READ_ATTRIBUTES
                | AccessMask::READ_EA
                | AccessMask::READ_CONTROL,
            file_attributes: 0x0,
            create_options: 0x40 | 0x200,
            share_access: ShareAccess::SHARE_READ,
            create_disposition: CreateDisposition::Open,
            path,
        };
        let session = tree_connection.session();
        let key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();

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
        Ok(FileHandle {
            oplock_level,
            offset: 0,
            tree_connection,
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
        let key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
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
    async fn send_close_raw(
        tree_connection: Arc<TreeConnection>,
        id: FileId,
    ) -> Result<(), std::io::Error> {
        let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Close);
        let session = tree_connection.session();
        let session_key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
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
}
impl AsyncRead for FileHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
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
impl AsyncSeek for FileHandle {
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

fn verify_close_header(header: &SyncHeader202Incoming) -> Result<(), ReadCloseError> {
    if header.command != Command202::Close || header.is_async() {
        Err(ReadCloseError::InvalidHeader)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct FileCreateRequest<'p> {
    oplock_level: Option<OplockLevel202>,
    impersonation_level: ImpersonationLevel,
    desired_access: AccessMask,
    file_attributes: u32,
    share_access: ShareAccess,
    create_disposition: CreateDisposition,
    create_options: u32,
    path: &'p str,
}
impl MessageBody for FileCreateRequest<'_> {
    fn size_hint(&self) -> usize {
        56 + (self.path.chars().count() * 2)
    }
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&57u16.to_le_bytes());
        w.push(0);
        let oplock_byte: u8 = match self.oplock_level {
            None => 0x00,
            Some(OplockLevel202::II) => 0x01,
            Some(OplockLevel202::Exclusive) => 0x08,
            Some(OplockLevel202::Batch) => 0x09,
        };
        w.push(oplock_byte);
        let imp_byte: u8 = match self.impersonation_level {
            ImpersonationLevel::Anonymous => 0x00,
            ImpersonationLevel::Identification => 0x01,
            ImpersonationLevel::Impersonation => 0x02,
            ImpersonationLevel::Delegate => 0x03,
        };
        w.extend_from_slice(&u32::from(imp_byte).to_le_bytes());
        w.extend_from_slice(&0u64.to_le_bytes());
        w.extend_from_slice(&0u64.to_le_bytes());
        w.extend_from_slice(&self.desired_access.0.to_le_bytes());
        w.extend_from_slice(&self.file_attributes.to_le_bytes());
        w.extend_from_slice(&self.share_access.0.to_le_bytes());
        w.extend_from_slice(&self.create_disposition.to_u32().to_le_bytes());
        // TODO create options
        w.extend_from_slice(&self.create_options.to_le_bytes());
        let path = crate::to_wide(self.path);
        let offset: u16 = 64 + 56;
        w.extend_from_slice(&offset.to_le_bytes());
        w.extend_from_slice(&(path.len() as u16).to_le_bytes());
        let create_contexts_offset: u32 = 0;
        w.extend_from_slice(&create_contexts_offset.to_le_bytes());
        w.extend_from_slice(&0u32.to_le_bytes());
        w.extend_from_slice(&path);
    }
}

#[derive(Debug)]
pub enum OpenError {
    Io(std::io::Error),
    InvalidMessage,
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
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
    const READ_DATA: Self = Self(0x01);
    const WRITE_DATA: Self = Self(0x02);
    const APPEND_DATA: Self = Self(0x04);
    const READ_EA: Self = Self(0x08);
    const WRITE_EA: Self = Self(0x10);
    const DELETE_CHILD: Self = Self(0x40);
    const EXECUTE: Self = Self(0x20);
    const READ_ATTRIBUTES: Self = Self(0x80);
    const WRITE_ATTRIBUTES: Self = Self(0x100);
    const DELETE: Self = Self(0x10000);
    const READ_CONTROL: Self = Self(0x20000);
    const WRITE_DAC: Self = Self(0x40000);
    const WRITE_OWNER: Self = Self(0x80000);
    const SYNCHRONIZE: Self = Self(0x100000);
    const ACCESS_SYSTEM_SECURITY: Self = Self(0x1000000);
    const MAXIMUM_ALLOWED: Self = Self(0x2000000);
    const GENERIC_ALL: Self = Self(0x10000000);
    const GENERIC_EXECUTE: Self = Self(0x20000000);
    const GENERIC_WRITE: Self = Self(0x40000000);
    const GENERIC_READ: Self = Self(0x80000000);

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
struct ShareAccess(u32);
impl ShareAccess {
    const SHARE_READ: Self = Self(0x01);
    const SHARE_WRITE: Self = Self(0x02);
    const SHARE_DELETE: Self = Self(0x04);
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

#[derive(Clone, Copy, Debug, Default)]
pub enum CreateDisposition {
    Supersede,
    #[default]
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}
impl CreateDisposition {
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Supersede => 0x00,
            Self::Open => 0x01,
            Self::Create => 0x02,
            Self::OpenIf => 0x03,
            Self::Overwrite => 0x04,
            Self::OverwriteIf => 0x05,
        }
    }
}

#[derive(Debug)]
struct CreateResponse {
    oplock_level: Option<OplockLevel202>,
    create_action: CreateActionTaken,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    allocation_size: u64,
    end_of_file: u64,
    attributes: u32,
    id: FileId,
}
impl CreateResponse {
    const STRUCTURE_SIZE: u16 = 89;
    fn read_from<R: Read>(r: &mut R) -> Result<Self, ReadError> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            return Err(ReadError::InvalidStructureSize);
        }
        let mut oplock = 0;
        r.read_exact(std::slice::from_mut(&mut oplock))?;
        let oplock_level = match oplock {
            0x00 => None,
            0x01 => Some(OplockLevel202::II),
            0x08 => Some(OplockLevel202::Exclusive),
            0x09 => Some(OplockLevel202::Batch),
            _ => return Err(ReadError::InvalidOplockLevel),
        };
        // flags
        r.read_exact(&mut [0])?;
        let create_action = match r.read_u32_le()? {
            0x00 => CreateActionTaken::Superseded,
            0x01 => CreateActionTaken::Opened,
            0x02 => CreateActionTaken::Created,
            0x03 => CreateActionTaken::Overwritten,
            _ => return Err(ReadError::InvalidCreateAction),
        };
        let creation_time = r.read_u64_le()?;
        let last_access_time = r.read_u64_le()?;
        let last_write_time = r.read_u64_le()?;
        let change_time = r.read_u64_le()?;
        let allocation_size = r.read_u64_le()?;
        let end_of_file = r.read_u64_le()?;
        let attributes = r.read_u32_le()?;
        let _ = r.read_u32_le()?;
        let mut persistent = [0u8; 8];
        r.read_exact(&mut persistent)?;
        let mut volatile = [0u8; 8];
        r.read_exact(&mut volatile)?;
        let id = FileId {
            persistent,
            volatile,
        };
        let create_contexts_offset = r.read_u32_le()?;
        let create_contexts_length = r.read_u32_le()?;
        let mut _ctx = vec![0; (create_contexts_length + create_contexts_offset) as usize];
        r.read_exact(&mut _ctx)?;
        Ok(CreateResponse {
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
        })
    }
}
#[derive(Debug)]
enum ReadError {
    Io(std::io::Error),
    InvalidStructureSize,
    InvalidOplockLevel,
    InvalidCreateAction,
}
impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug)]
enum CreateActionTaken {
    Superseded,
    Opened,
    Created,
    Overwritten,
}

#[derive(Clone, Copy, Debug)]
pub struct FileId {
    persistent: [u8; 8],
    volatile: [u8; 8],
}
