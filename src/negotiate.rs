use crate::{ReadLe, message::MessageBody};
use std::io::{Read, Write};

/// Negotiate request in SMB2020 must set client ID to 0
#[derive(Debug)]
pub struct NegotiateRequest202 {
    pub capabilities: u32,
}
impl NegotiateRequest202 {
    fn write_into<W: Write>(&self, mut w: W) -> Result<(), WriteError> {
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
    type Err = WriteError;
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err> {
        self.write_into(w)
    }
}

#[derive(Debug)]
pub enum WriteError {
    Io(std::io::Error),
}
impl From<std::io::Error> for WriteError {
    fn from(value: std::io::Error) -> Self {
        WriteError::Io(value)
    }
}

#[derive(Debug)]
pub struct NegotiateResponse {
    pub security_mode: SecurityMode,
    pub dialect: Dialect,
}
impl NegotiateResponse {
    const STRUCTURE_SIZE: u16 = 65;
    fn read_from<R: Read>(mut r: R) -> Result<Self, NegotiateError> {
        if r.read_u16()? != Self::STRUCTURE_SIZE {
            return Err(NegotiateError::InvalidSize);
        }
        let security_mode = SecurityMode::from_value(r.read_u16()?);
        let dialect = Dialect::from_value(r.read_u16()?).ok_or(NegotiateError::InvalidDialect)?;
        // skip reserved
        r.read_exact(&mut [0u8; 2])?;
        let mut server_guid = [0u8; 16];
        r.read_exact(&mut server_guid)?;
        todo!()
    }
}

#[derive(Debug)]
pub enum NegotiateError {
    Io(std::io::Error),
    InvalidSize,
    InvalidDialect,
}
impl From<std::io::Error> for NegotiateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SecurityMode {
    None,
    SigningEnabled,
    SigningRequired,
}
impl SecurityMode {
    fn from_value(i: u16) -> Self {
        if i & 0x02 != 0 {
            Self::SigningRequired
        } else if i & 0x01 != 0 {
            Self::SigningEnabled
        } else {
            Self::None
        }
    }
}
#[derive(Debug)]
pub enum Dialect {
    SMB2020,
    SMB21,
    SMB30,
    SMB302,
    SMB311,
    Wildcard,
}
impl Dialect {
    fn from_value(i: u16) -> Option<Self> {
        match i {
            0x0202 => Some(Self::SMB2020),
            0x0210 => Some(Self::SMB21),
            0x0300 => Some(Self::SMB30),
            0x0302 => Some(Self::SMB302),
            0x0311 => Some(Self::SMB311),
            0x02FF => Some(Self::Wildcard),
            _ => None,
        }
    }
}
