use uuid::Uuid;

use crate::{ReadIntLe, message::MessageBody, sign::SecurityMode};
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug)]
pub struct Capabilities(u32);
impl Capabilities {
    pub const NONE: Self = Self(0);
    pub const SMB2_GLOBAL_CAP_LARGE_MTU: Self = Self(0x04);
}

/// Negotiate request in SMB2020 must set client ID to 0
#[derive(Debug)]
pub struct NegotiateRequest<'d> {
    pub capabilities: Capabilities,
    pub security_mode: SecurityMode,
    pub dialects: &'d [Dialect],
}

impl MessageBody for NegotiateRequest<'_> {
    fn write_to(&self, w: &mut Vec<u8>) {
        // structure size
        w.extend_from_slice(&36u16.to_le_bytes());
        // dialect count
        w.extend_from_slice(&(self.dialects.len() as u16).to_le_bytes());
        // Empty security mode
        w.extend_from_slice(&(self.security_mode as u16).to_le_bytes());
        // Reserved
        w.extend_from_slice(&0u16.to_le_bytes());
        // Capabilities
        w.extend_from_slice(&self.capabilities.0.to_le_bytes());
        w.extend_from_slice(&[0u8; 16]);
        // client start time
        w.extend_from_slice(&0u64.to_le_bytes());
        // dialect 202
        for dialect in self.dialects {
            w.extend_from_slice(&dialect.to_int().to_le_bytes());
        }
        w.extend_from_slice(&0x0202u16.to_le_bytes());
    }
    fn size_hint(&self) -> usize {
        38
    }
    fn send_payload_size(&self) -> u32 {
        0
    }
    fn expected_response_payload_size(&self) -> u32 {
        0
    }
}

#[derive(Debug)]
pub struct NegotiateResponse {
    pub security_mode: SecurityMode,
    pub dialect: Dialect,
    pub server_guid: Uuid,
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    pub sec_buffer: Box<[u8]>,
}
impl NegotiateResponse {
    const STRUCTURE_SIZE: u16 = 65;
    pub fn read_from<R: Read + Seek>(r: &mut R) -> Result<Self, NegotiateError> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            return Err(NegotiateError::InvalidSize);
        }
        let security_mode = SecurityMode::from_value(r.read_u16_le()?);
        let dialect = Dialect::from_value(r.read_u16_le()?).ok_or(NegotiateError::InvalidDialect)?;
        // skip reserved
        r.seek(SeekFrom::Current(2))?;
        let mut server_guid = [0u8; 16];
        r.read_exact(&mut server_guid)?;
        let server_guid = Uuid::from_bytes(server_guid);
        let capabilities = r.read_u32_le()?;
        let max_transact_size = r.read_u32_le()?;
        let max_read_size = r.read_u32_le()?;
        let max_write_size = r.read_u32_le()?;
        let system_time = r.read_u64_le()?;
        let server_start_time = r.read_u64_le()?;
        let secbuf_offset = r.read_u16_le()?;
        let secbuf_length = r.read_u16_le()?;
        // ignore reserved and padding
        r.seek(SeekFrom::Start((secbuf_offset - 64) as u64))?;
        let mut sec_buffer = vec![0; secbuf_length as usize].into_boxed_slice();
        r.read_exact(&mut sec_buffer)?;

        Ok(Self {
            security_mode,
            dialect,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            sec_buffer,
        })
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

#[derive(Clone, Copy, Debug, PartialEq)]
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
    fn to_int(self) -> u16 {
        match self {
            Dialect::SMB2020 => 0x0202,
            Dialect::SMB21 => 0x0210,
            Dialect::SMB30 => 0x0300,
            Dialect::SMB302 => 0x0302,
            Dialect::SMB311 => 0x0311,
            Dialect::Wildcard => todo!(),
        }
    }
}
