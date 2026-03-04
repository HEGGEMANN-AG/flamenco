use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    num::NonZero,
    ops::BitOr,
};

use crate::{
    ReadLe,
    client::Client202,
    error::{ErrorResponse2, ServerError},
    file::{
        close::{CloseRequest, CloseResponse},
        read::{ReadFileError, ReadRequest, ReadResponse, ReadResponseError},
    },
    header::{Command202, SyncHeader202Outgoing},
    message::{
        MessageBody, ReadError as MsgReadError, Validation, WriteError, read_202_message,
        write_202_message,
    },
    tree::TreeConnection,
};

mod close;
mod read;

#[derive(Debug)]
pub struct FileHandle<'con, 'session, 'tree, CL> {
    tree_connection: &'tree mut TreeConnection<'con, 'session, CL>,
    id: FileId,
    oplock_level: Option<OplockLevel202>,
    offset: u64,
    allocation_size: u64,
    end_of_file: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
}
impl<CL> FileHandle<'_, '_, '_, CL> {
    pub(crate) fn new<'tree, 'client, 'con, 'session>(
        tree_connection: &'tree mut TreeConnection<'con, 'session, CL>,
        path: &str,
    ) -> Result<FileHandle<'con, 'session, 'tree, CL>, OpenError> {
        let header = SyncHeader202Outgoing::from_tree_con(tree_connection, Command202::Create);
        let request_body = FileCreateRequest {
            oplock_level: Some(OplockLevel202::Batch),
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: AccessMask::READ_DATA
                | AccessMask::READ_ATTRIBUTES
                | AccessMask::READ_EA
                | AccessMask::READ_CONTROL,
            file_attributes: 0x0,
            create_options: 0x40 | 0x200,
            share_access: ShareAccess::SHARE_READ | ShareAccess::SHARE_WRITE,
            create_disposition: CreateDisposition::Open,
            path,
        };
        let session = tree_connection.session_mut();
        let key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
        write_202_message(
            &mut session.connection.tcp,
            key,
            header,
            &request_body,
            false,
        )
        .unwrap();
        let (header, body) =
            read_202_message(&mut session.connection.tcp, Validation::from(key)).unwrap();
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &body));
        }
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
        } = CreateResponse::read_from(body.as_ref()).unwrap();
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
        })
    }
    pub fn read_raw(
        &mut self,
        length: u32,
        minimum_count: u32,
    ) -> Result<Box<[u8]>, ReadFileError> {
        let header = SyncHeader202Outgoing::from_tree_con(self.tree_connection, Command202::Read);
        let session = self.tree_connection.session_mut();
        let key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
        write_202_message(
            &mut session.connection.tcp,
            key,
            header,
            &ReadRequest {
                length,
                offset: self.offset,
                id: self.id,
                minimum_count,
            },
            true,
        )
        .map_err(|e| match e {
            WriteError::Connection(io) => ReadFileError::Io(io),
            WriteError::MessageTooLong => ReadFileError::InvalidMessage,
        })?;
        let (header, body) = read_202_message(&mut session.connection.tcp, Validation::from(key))
            .map_err(|e| match e {
            MsgReadError::NetBIOS
            | MsgReadError::NotSigned
            | MsgReadError::InvalidSignature
            | MsgReadError::InvalidlySignedMessage => ReadFileError::InvalidMessage,
            MsgReadError::Connection(io) => ReadFileError::Io(io),
        })?;
        if let Some(code) = NonZero::new(header.status) {
            return Err(ServerError::handle_error_body(code, &body));
        }
        match ReadResponse::read_from(Cursor::new(body)) {
            Ok(ok) => Ok(ok.into_inner()),
            Err(ReadResponseError::Io(io)) => Err(ReadFileError::Io(io)),
            Err(ReadResponseError::InvalidMessage) => Err(ReadFileError::InvalidMessage),
        }
    }
    fn send_close(&mut self) -> Result<(), std::io::Error> {
        let header = SyncHeader202Outgoing::from_tree_con(self.tree_connection, Command202::Close);
        let session = self.tree_connection.session_mut();
        let session_key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
        write_202_message(
            &mut session.connection.tcp,
            session_key,
            header,
            &CloseRequest { id: self.id },
            false,
        )
        .unwrap();
        let (header, body) =
            read_202_message(&mut session.connection.tcp, Validation::from(session_key)).unwrap();
        if let Some(code) = NonZero::new(header.status) {
            panic!("Error with code {code}");
        }
        let _body = CloseResponse::read_from(body.as_ref()).unwrap();
        Ok(())
    }
    pub fn close(mut self) -> Result<(), std::io::Error> {
        self.send_close()
    }
}
impl<CL> Drop for FileHandle<'_, '_, '_, CL> {
    fn drop(&mut self) {
        let _ = self.send_close();
    }
}
impl<CL> Read for FileHandle<'_, '_, '_, CL> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let until_end = (self.end_of_file - self.offset)
            .try_into()
            .unwrap_or(u32::MAX);
        let len = buf.len().try_into().unwrap_or(u32::MAX).min(until_end);
        match self.read_raw(len, 0) {
            Ok(outbuf) => {
                assert!(outbuf.len() <= len as usize);
                self.offset += outbuf.len() as u64;
                buf[0..outbuf.len()].copy_from_slice(&outbuf);
                Ok(outbuf.len())
            }
            Err(rd) => Err(rd.collapse_to_io_error()),
        }
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let until_end = (self.end_of_file - self.offset)
            .try_into()
            .unwrap_or(u32::MAX);
        let len = buf.len().try_into().unwrap_or(u32::MAX).min(until_end);
        match self.read_raw(len, len) {
            Ok(outbuf) => {
                assert!(outbuf.len() <= len as usize);
                self.offset += outbuf.len() as u64;
                buf[0..outbuf.len()].copy_from_slice(&outbuf);
                Ok(())
            }
            Err(rf) => Err(rf.collapse_to_io_error()),
        }
    }
}
impl<CL> Seek for FileHandle<'_, '_, '_, CL> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(s) => s,
            SeekFrom::Current(c) => self.offset.saturating_add_signed(c),
            SeekFrom::End(c) => self.end_of_file.saturating_add_signed(c),
        };
        self.offset = new;
        Ok(new)
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
impl FileCreateRequest<'_> {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), std::io::Error> {
        w.write_all(&57u16.to_le_bytes())?;
        w.write_all(&[0])?;
        let oplock_byte: u8 = match self.oplock_level {
            None => 0x00,
            Some(OplockLevel202::II) => 0x01,
            Some(OplockLevel202::Exclusive) => 0x08,
            Some(OplockLevel202::Batch) => 0x09,
        };
        w.write_all(&[oplock_byte])?;
        let imp_byte: u8 = match self.impersonation_level {
            ImpersonationLevel::Anonymous => 0x00,
            ImpersonationLevel::Identification => 0x01,
            ImpersonationLevel::Impersonation => 0x02,
            ImpersonationLevel::Delegate => 0x03,
        };
        w.write_all(&u32::from(imp_byte).to_le_bytes())?;
        w.write_all(&0u64.to_le_bytes())?;
        w.write_all(&0u64.to_le_bytes())?;
        w.write_all(&self.desired_access.0.to_le_bytes())?;
        w.write_all(&self.file_attributes.to_le_bytes())?;
        w.write_all(&self.share_access.0.to_le_bytes())?;
        w.write_all(&self.create_disposition.to_u32().to_le_bytes())?;
        // TODO create options
        w.write_all(&self.create_options.to_le_bytes())?;
        let path = crate::to_wide(self.path);
        let offset: u16 = 64 + 56;
        w.write_all(&offset.to_le_bytes())?;
        w.write_all(&(path.len() as u16).to_le_bytes())?;
        let create_contexts_offset: u32 = 0;
        w.write_all(&create_contexts_offset.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&path)?;
        Ok(())
    }
}
impl MessageBody for FileCreateRequest<'_> {
    type Err = std::io::Error;
    fn size_hint(&self) -> usize {
        56 + (self.path.chars().count() * 2)
    }
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
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
    fn read_from<R: Read>(mut r: R) -> Result<Self, ReadError> {
        if r.read_u16()? != Self::STRUCTURE_SIZE {
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
        let create_action = match r.read_u32()? {
            0x00 => CreateActionTaken::Superseded,
            0x01 => CreateActionTaken::Opened,
            0x02 => CreateActionTaken::Created,
            0x03 => CreateActionTaken::Overwritten,
            _ => return Err(ReadError::InvalidCreateAction),
        };
        let creation_time = r.read_u64()?;
        let last_access_time = r.read_u64()?;
        let last_write_time = r.read_u64()?;
        let change_time = r.read_u64()?;
        let allocation_size = r.read_u64()?;
        let end_of_file = r.read_u64()?;
        let attributes = r.read_u32()?;
        let _ = r.read_u32()?;
        let mut persistent = [0u8; 8];
        r.read_exact(&mut persistent)?;
        let mut volatile = [0u8; 8];
        r.read_exact(&mut volatile)?;
        let id = FileId {
            persistent,
            volatile,
        };
        let create_contexts_offset = r.read_u32()?;
        let create_contexts_length = r.read_u32()?;
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
