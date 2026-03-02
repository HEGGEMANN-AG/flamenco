use std::{
    io::{Read, Write},
    num::NonZero,
    ops::BitOr,
};

use crate::{
    ReadLe,
    error::{ErrorResponse2, ServerError},
    header::{Command202, SyncHeader202Outgoing},
    message::{MessageBody, Validation, read_202_message, write_202_message},
    tree::TreeConnection,
};

#[derive(Debug)]
pub struct FileHandle<'client, 'con, 'cred, 'session, 'tree> {
    tree_connection: &'tree mut TreeConnection<'client, 'con, 'cred, 'session>,
    id: FileId,
    allocation_size: u64,
    end_of_file: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
}
impl FileHandle<'_, '_, '_, '_, '_> {
    pub(crate) fn new<'tree, 'client, 'con, 'cred, 'session>(
        tree_connection: &'tree mut TreeConnection<'client, 'con, 'cred, 'session>,
        path: &str,
    ) -> Result<FileHandle<'client, 'con, 'cred, 'session, 'tree>, OpenError> {
        let header = SyncHeader202Outgoing::from_tree_con(tree_connection, Command202::Create);
        let request_body = FileCreateRequest {
            oplock_level: None,
            impersonation_level: ImpersonationLevel::Identification,
            desired_access: AccessMask::READ_DATA,
            file_attributes: 0,
            share_access: ShareAccess::SHARE_READ,
            create_disposition: CreateDisposition::Open,
            path,
        };
        let session = tree_connection.session_mut();
        let key = session
            .requires_signing()
            .then_some(session.session_key())
            .copied();
        write_202_message(&mut session.connection.tcp, key, header, &request_body).unwrap();
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
        )
        .unwrap();
        let (header, body) =
            read_202_message(&mut session.connection.tcp, Validation::from(session_key)).unwrap();
        if let Some(code) = NonZero::new(header.status) {
            panic!("Error with code {code}");
        }
        let body = CloseResponse::read_from(body.as_ref()).unwrap();
        dbg!(body);
        Ok(())
    }
    pub fn close(mut self) -> Result<(), std::io::Error> {
        self.send_close()
    }
}
impl Drop for FileHandle<'_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        let _ = self.send_close();
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
    path: &'p str,
}
impl FileCreateRequest<'_> {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), std::io::Error> {
        w.write_all(&57u16.to_le_bytes())?;
        w.write_all(&[0])?;
        let oplock_byte = match self.oplock_level {
            None => 0x00,
            Some(OplockLevel202::II) => 0x01,
            Some(OplockLevel202::Exclusive) => 0x08,
            Some(OplockLevel202::Batch) => 0x09,
        };
        w.write_all(&[oplock_byte])?;
        let imp_byte = match self.impersonation_level {
            ImpersonationLevel::Anonymous => 0x00,
            ImpersonationLevel::Identification => 0x01,
            ImpersonationLevel::Impersonation => 0x02,
            ImpersonationLevel::Delegate => 0x03,
        };
        w.write_all(&(imp_byte as u32).to_le_bytes())?;
        w.write_all(&0u64.to_le_bytes())?;
        w.write_all(&0u64.to_le_bytes())?;
        w.write_all(&self.desired_access.0.to_le_bytes())?;
        w.write_all(&self.file_attributes.to_le_bytes())?;
        w.write_all(&self.share_access.0.to_le_bytes())?;
        w.write_all(&self.create_disposition.to_u32().to_le_bytes())?;
        // TODO create options
        w.write_all(&0u32.to_le_bytes())?;
        let path = crate::to_wide(self.path);
        let offset: u16 = 64 + 56;
        w.write_all(&offset.to_le_bytes())?;
        w.write_all(&(path.len() as u16).to_le_bytes())?;
        // todo create contexts
        w.write_all(&0u32.to_le_bytes())?;
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
        let persistent = r.read_u64()?;
        let volatile = r.read_u64()?;
        let id = FileId {
            persistent,
            volatile,
        };
        let create_contexts_offset = r.read_u32()?;
        let create_contexts_length = r.read_u32()?;
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
    persistent: u64,
    volatile: u64,
}

#[derive(Clone, Copy, Debug)]
struct CloseRequest {
    id: FileId,
}
impl CloseRequest {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), std::io::Error> {
        w.write_all(&24u16.to_le_bytes())?;
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        let FileId {
            persistent,
            volatile,
        } = self.id;
        w.write_all(&persistent.to_le_bytes())?;
        w.write_all(&volatile.to_le_bytes())?;
        Ok(())
    }
}
impl MessageBody for CloseRequest {
    type Err = std::io::Error;
    fn size_hint(&self) -> usize {
        24
    }
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Clone, Debug)]
struct CloseResponse {
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    allocation_size: u64,
    end_of_file: u64,
}
impl CloseResponse {
    fn read_from<R: Read>(mut r: R) -> Result<Self, ReadCloseError> {
        if r.read_u16()? != 60 {
            return Err(ReadCloseError::InvalidStructureSize);
        }
        let _flags = r.read_u16()?;
        let creation_time = r.read_u64()?;
        let last_access_time = r.read_u64()?;
        let last_write_time = r.read_u64()?;
        let change_time = r.read_u64()?;
        let allocation_size = r.read_u64()?;
        let end_of_file = r.read_u64()?;
        let _file_attributes = r.read_u32()?;
        Ok(Self {
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
        })
    }
}

#[derive(Debug)]
pub enum ReadCloseError {
    Io(std::io::Error),
    InvalidStructureSize,
}
impl From<std::io::Error> for ReadCloseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
