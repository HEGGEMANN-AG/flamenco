use std::{
    io::{ErrorKind, Read, Write},
    ops::DerefMut,
};

use uuid::Uuid;

use crate::{
    Smb2ClientMessage, byteorder::LittleEndian, dialect::Dialect, header::Smb2SyncHeader, security::SecurityMode16,
};

pub struct NegotiateRequest {
    pub security_mode: SecurityMode16,
    pub capabilities: u32,
    pub client_guid: Uuid,
    pub dialects: Vec<Dialect>,
}
impl NegotiateRequest {
    const SIZE_ON_WIRE: u16 = 36;
    const ZEROS: [u8; 8] = [0; 8];
    fn write_to<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        Self::SIZE_ON_WIRE.write_le(&mut writer)?;
        assert!(!self.dialects.is_empty());
        (self.dialects.len() as u16).write_le(&mut writer)?;
        self.security_mode.as_u16().write_le(&mut writer)?;
        // reserved field
        0u16.write_le(&mut writer)?;
        self.capabilities.write_le(&mut writer)?;
        writer.write_all(&self.client_guid.into_bytes())?;
        // client start time
        0u64.write_le(&mut writer)?;
        for dialect in &self.dialects {
            (*dialect as u16).write_le(&mut writer)?;
        }
        let padding_bytes = (self.dialects.len() * 16) % 64 / 8;
        writer.write_all(&Self::ZEROS[0..padding_bytes])?;
        Ok(())
    }
}
impl Smb2ClientMessage for NegotiateRequest {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.write_to(writer)
    }
    fn size_hint(&self) -> usize {
        Self::SIZE_ON_WIRE as usize
    }
}

#[derive(Debug)]
pub struct NegotiateResponse {
    security_mode: SecurityMode16,
    dialect_revision: Dialect,
    server_guid: [u8; 16],
    capabilities: u32,
    max_transaction_size: u32,
    max_read_size: u32,
    max_write_size: u32,
    system_time: u64,
    server_start_time: u64,
    security_buffer: Box<[u8]>,
}
impl NegotiateResponse {
    const SIZE_ON_WIRE: u16 = 65;
    const ACTUAL_SIZE_ON_WIRE: usize = 64;
    pub fn read_from<R: Read>(r: &mut impl DerefMut<Target = R>) -> std::io::Result<Self> {
        let mut r = r.deref_mut();
        let size = u16::read_le(&mut r)?;
        assert_eq!(size, Self::SIZE_ON_WIRE);
        let security_mode = SecurityMode16::from_u16(u16::read_le(&mut r)?)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "invalid security mode"))?;
        let dialect_revision = Dialect::from_u16(u16::read_le(&mut r)?)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "invalid dialect"))?;
        let mut _ignored = u16::read_le(&mut r)?;
        let mut server_guid: [u8; 16] = Default::default();
        r.read_exact(&mut server_guid)?;
        let capabilities = u32::read_le(&mut r)?;
        let max_transaction_size = u32::read_le(&mut r)?;
        let max_read_size = u32::read_le(&mut r)?;
        let max_write_size = u32::read_le(&mut r)?;
        let system_time = u64::read_le(&mut r)?;
        let server_start_time = u64::read_le(&mut r)?;
        let security_buffer_offset = u16::read_le(&mut r)?;
        let security_buffer_length = u16::read_le(&mut r)?;
        let _negotiate_context_offset = u32::read_le(&mut r)?;

        let mut _eat_padding =
            vec![0; (security_buffer_offset - Smb2SyncHeader::SIZE_ON_WIRE) as usize - Self::ACTUAL_SIZE_ON_WIRE]
                .into_boxed_slice();
        r.read_exact(&mut _eat_padding)?;
        drop(_eat_padding);

        let mut security_buffer = vec![0; security_buffer_length as usize].into_boxed_slice();
        r.read_exact(&mut security_buffer)?;

        Ok(Self {
            security_mode,
            dialect_revision,
            server_guid,
            capabilities,
            max_transaction_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
            security_buffer,
        })
    }
    pub fn security_buffer(&self) -> Option<&[u8]> {
        (!self.security_buffer.is_empty()).then_some(&self.security_buffer)
    }
    pub fn is_signing_required(&self) -> bool {
        self.security_mode.signing_required()
    }
}
