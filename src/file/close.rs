use std::io::Read;

use crate::{ReadIntLe, file::FileId, message::MessageBody};

#[derive(Clone, Copy, Debug)]
pub struct CloseRequest {
    pub id: FileId,
}
impl MessageBody for CloseRequest {
    fn size_hint(&self) -> usize {
        24
    }
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&24u16.to_le_bytes());
        w.extend_from_slice(&0u16.to_le_bytes());
        w.extend_from_slice(&0u32.to_le_bytes());
        let FileId { persistent, volatile } = self.id;
        w.extend_from_slice(&persistent);
        w.extend_from_slice(&volatile);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CloseResponse {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
}
impl CloseResponse {
    pub(crate) fn read_from<R: Read>(r: &mut R) -> Result<Self, ReadCloseError> {
        if r.read_u16_le()? != 60 {
            return Err(ReadCloseError::InvalidStructureSize);
        }
        let _flags = r.read_u16_le()?;
        let creation_time = r.read_u64_le()?;
        let last_access_time = r.read_u64_le()?;
        let last_write_time = r.read_u64_le()?;
        let change_time = r.read_u64_le()?;
        let allocation_size = r.read_u64_le()?;
        let end_of_file = r.read_u64_le()?;
        let _file_attributes = r.read_u32_le()?;
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
    InvalidHeader,
    InvalidStructureSize,
}
impl From<std::io::Error> for ReadCloseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
