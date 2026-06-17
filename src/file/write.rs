use std::{
    io::{Read, Seek},
    num::NonZero,
};

#[cfg(feature = "tracing")]
use tracing::error;

use crate::{
    ReadIntLe,
    error::{ErrorResponse2, ServerError},
    file::FileId,
    message::MessageBody,
};

pub struct WriteRequest<'w> {
    pub offset: u64,
    pub id: FileId,
    /// set to false on SMB202
    pub write_trough: bool,
    pub data: &'w [u8],
}
impl WriteRequest<'_> {
    const STRUCTURE_SIZE: u16 = 49;
}
impl MessageBody for WriteRequest<'_> {
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&Self::STRUCTURE_SIZE.to_le_bytes());
        w.extend_from_slice(&(64u16 + 48u16).to_le_bytes());
        w.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        w.extend_from_slice(&self.offset.to_le_bytes());
        w.extend_from_slice(&self.id.persistent);
        w.extend_from_slice(&self.id.volatile);
        // Channel
        w.extend_from_slice(&0u32.to_le_bytes());
        // Rem bytes
        w.extend_from_slice(&0u32.to_le_bytes());
        // Write channel info offset
        w.extend_from_slice(&0u16.to_le_bytes());
        // Write channel info length
        w.extend_from_slice(&0u16.to_le_bytes());
        let flags: u32 = if self.write_trough { 0x1 } else { 0x0 };
        w.extend_from_slice(&flags.to_le_bytes());
        w.extend_from_slice(self.data);
    }

    fn send_payload_size(&self) -> u32 {
        self.data.len() as u32
    }

    fn expected_response_payload_size(&self) -> u32 {
        0
    }
}

#[derive(Debug)]
pub struct WriteResponse {
    pub count: u32,
}
impl WriteResponse {
    const STRUCTURE_SIZE: u16 = 17;
    pub fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, WriteFileError> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            return Err(WriteFileError::InvalidMessage);
        }
        let mut buf = [0; 2];
        // reserved
        r.read_exact(&mut buf)?;
        let count = r.read_u32_le()?;
        let _remaining = r.read_u32_le()?;
        let _ignored = r.read_u32_le()?;
        Ok(Self { count })
    }
}

#[derive(Debug)]
pub enum WriteFileError {
    Io(std::io::Error),
    InvalidMessage,
    NotEnoughCredits,
    #[expect(dead_code)]
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl From<std::io::Error> for WriteFileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl ServerError for WriteFileError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }

    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
}
impl WriteFileError {
    pub fn collapse_to_io_error(self) -> std::io::Error {
        match self {
            Self::InvalidMessage => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "server sent an invalid message")
            }
            Self::Io(io) => io,
            #[allow(unused_variables)]
            Self::ServerError { code, .. } => {
                #[cfg(feature = "tracing")]
                error!("Server sent protocol error code {code}");
                std::io::Error::other("server sent a protocol error")
            }
            Self::NotEnoughCredits => std::io::Error::new(std::io::ErrorKind::FileTooLarge, "not enough credits"),
        }
    }
}
