use crate::message::MessageBody;
use std::io::Write;

/// Negotiate request in SMB2020 must set client ID to 0
#[derive(Debug)]
pub struct NegotiateRequest202 {
    pub capabilities: u32,
}
impl NegotiateRequest202 {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), Error> {
        // structure size
        w.write_all(&36u16.to_le_bytes())?;
        // dialect count
        w.write_all(&1u16.to_le_bytes())?;
        // Empty security mode
        w.write_all(&0u16.to_le_bytes())?;
        // Reserved
        w.write_all(&0u16.to_le_bytes())?;
        w.write_all(&self.capabilities.to_le_bytes())?;
        w.write_all(&[0u8; 16])?;
        // client start time
        w.write_all(&0u64.to_le_bytes())?;
        // dialect 202
        w.write_all(&0x0202u16.to_le_bytes())?;
        Ok(())
    }
}

impl MessageBody for NegotiateRequest202 {
    type Err = Error;
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}
