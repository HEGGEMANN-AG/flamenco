use std::io::{Read, Write};

use crate::{ReadLe, file::FileId, message::MessageBody};

#[derive(Clone, Copy, Debug)]
pub struct CloseRequest {
    pub id: FileId,
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
        w.write_all(&persistent)?;
        w.write_all(&volatile)?;
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
pub struct CloseResponse {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
}
impl CloseResponse {
    pub(crate) fn read_from<R: Read>(mut r: R) -> Result<Self, ReadCloseError> {
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
