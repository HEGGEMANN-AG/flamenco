use std::io::Read;

use crate::{
    ReadIntLe,
    attributes::FileAttributes,
    file::{AccessMask, FileId, ImpersonationLevel, OplockLevel202, ShareAccess},
    message::MessageBody,
};

#[derive(Debug)]
pub(crate) struct FileCreateRequest<'p> {
    pub(crate) oplock_level: Option<OplockLevel202>,
    pub(crate) impersonation_level: ImpersonationLevel,
    pub(crate) desired_access: AccessMask,
    pub(crate) file_attributes: FileAttributes,
    pub(crate) share_access: ShareAccess,
    pub(crate) create_disposition: CreateDisposition,
    pub(crate) create_options: u32,
    pub(crate) path: &'p str,
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
        w.extend_from_slice(&self.file_attributes.to_int().to_le_bytes());
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

#[derive(Debug)]
pub(crate) struct CreateResponse {
    pub(crate) oplock_level: Option<OplockLevel202>,
    pub(crate) create_action: CreateActionTaken,
    pub(crate) creation_time: u64,
    pub(crate) last_access_time: u64,
    pub(crate) last_write_time: u64,
    pub(crate) change_time: u64,
    pub(crate) allocation_size: u64,
    pub(crate) end_of_file: u64,
    pub(crate) attributes: FileAttributes,
    pub(crate) id: FileId,
}
impl CreateResponse {
    const STRUCTURE_SIZE: u16 = 89;
    pub(crate) fn read_from<R: Read>(r: &mut R) -> Result<Self, ReadError> {
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
        let attributes = FileAttributes::from_int(r.read_u32_le()?);
        let _ = r.read_u32_le()?;
        let mut persistent = [0u8; 8];
        r.read_exact(&mut persistent)?;
        let mut volatile = [0u8; 8];
        r.read_exact(&mut volatile)?;
        let id = FileId { persistent, volatile };
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
pub(crate) enum ReadError {
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

#[derive(Clone, Copy, Debug, Default)]
pub enum CreateDisposition {
    /// If the file already exists, supersede it; otherwise, create the file.
    Supersede,
    #[default]
    /// If the file already exists, return success; otherwise, fail the operation.
    Open,
    /// If the file already exists, fail the operation; otherwise, create the file.
    Create,
    /// Open the file if it already exists; otherwise, create the file.
    OpenIf,
    /// Overwrite the file if it already exists; otherwise, fail the operation.
    Overwrite,
    /// Overwrite the file if it already exists; otherwise, create the file.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateActionTaken {
    Superseded,
    Opened,
    Created,
    Overwritten,
}
