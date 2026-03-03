use std::{
    io::{Read, Seek, SeekFrom, Write},
    num::NonZero,
};

use crate::{
    ReadLe,
    error::{ErrorResponse2, ServerError},
    file::FileId,
    message::MessageBody,
};

#[derive(Debug)]
pub struct ReadRequest {
    pub length: u32,
    pub offset: u64,
    pub id: FileId,
    pub minimum_count: u32,
}
impl ReadRequest {
    const STRUCTURE_SIZE: u16 = 49;
    pub fn write_into<W: Write>(&self, mut w: W) -> Result<(), std::io::Error> {
        w.write_all(&Self::STRUCTURE_SIZE.to_le_bytes())?;
        w.write_all(&[64 + 16])?;
        w.write_all(&[0])?;
        w.write_all(&self.length.to_le_bytes())?;
        w.write_all(&self.offset.to_le_bytes())?;
        let FileId {
            persistent,
            volatile,
        } = self.id;
        w.write_all(&persistent)?;
        w.write_all(&volatile)?;
        w.write_all(&self.minimum_count.to_le_bytes())?;
        // Channel
        w.write_all(&0u32.to_le_bytes())?;
        // Remaining Bytes
        w.write_all(&0u32.to_le_bytes())?;
        // Channel Info Offset
        w.write_all(&0u16.to_le_bytes())?;
        // Channel Info Length
        w.write_all(&0u16.to_le_bytes())?;
        Ok(())
    }
}
impl MessageBody for ReadRequest {
    type Err = std::io::Error;
    fn size_hint(&self) -> usize {
        48
    }
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Debug)]
pub struct ReadResponse(Box<[u8]>);
impl ReadResponse {
    const STRUCTURE_SIZE: u16 = 49;
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn into_inner(self) -> Box<[u8]> {
        self.0
    }
    pub fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, std::io::Error> {
        if r.read_u16()? != Self::STRUCTURE_SIZE {
            panic!("Invalid structure size");
        }
        let mut offset = 0;
        r.read_exact(std::slice::from_mut(&mut offset))?;
        r.seek_relative(1)?;
        let data_length = r.read_u32()?;
        let _data_remaining = r.read_u32()?;
        r.seek_relative(4)?;
        if offset < 64 + 16 {
            panic!("Offset into data");
        } else {
            let mut buffer = vec![0; data_length as usize].into_boxed_slice();
            r.seek(SeekFrom::Start((offset - 64) as u64))?;
            r.read_exact(buffer.as_mut())?;
            Ok(Self(buffer))
        }
    }
}

#[derive(Debug)]
pub enum ReadFileError {
    Io(std::io::Error),
    InvalidMessage,
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl From<std::io::Error> for ReadFileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl ServerError for ReadFileError {
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }
}
