use std::io::{ErrorKind, Read, Write};

use crate::{Smb2ClientMessage, byteorder::LittleEndian, security::SecurityMode8};

#[derive(Debug)]
pub struct SessionSetupRequest {
    pub flags: u8,
    pub security_mode: SecurityMode8,
    pub capabilities: u32,
    pub previous_session_id: u64,
    pub security_buffer: Box<[u8]>,
}
impl SessionSetupRequest {
    fn write_to<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        25u16.write_le(&mut writer)?;
        writer.write_all(&[self.flags, self.security_mode.as_u8()])?;
        self.capabilities.write_le(&mut writer)?;
        // Channel, must be reserved
        0u32.write_le(&mut writer)?;
        // Security buffer offset
        (64u16 + 24).write_le(&mut writer)?;
        (self.security_buffer.len() as u16).write_le(&mut writer)?;
        self.previous_session_id.write_le(&mut writer)?;
        writer.write_all(&self.security_buffer)?;
        Ok(())
    }
}

impl Smb2ClientMessage for SessionSetupRequest {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.write_to(writer)
    }
    fn size_hint(&self) -> usize {
        25
    }
}

#[derive(Debug)]
pub struct SessionSetupResponse {
    pub session_flags: SessionFlags,
    security_buffer: Box<[u8]>,
}
impl SessionSetupResponse {
    pub fn read_from<R: Read>(mut r: R) -> std::io::Result<Self> {
        let size = u16::read_le(&mut r)?;
        assert_eq!(size, 9);
        let session_flags = SessionFlags::from_u16(u16::read_le(&mut r)?)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "invalid session flags"))?;
        let offset = u16::read_le(&mut r)?;
        let length = u16::read_le(&mut r)?;
        let mut security_buffer = vec![0; length as usize].into_boxed_slice();
        let mut _ignore = vec![0; offset as usize - 64 - 8];
        r.read_exact(&mut _ignore)?;
        r.read_exact(&mut security_buffer)?;
        Ok(Self {
            session_flags,
            security_buffer,
        })
    }
    pub fn security_token(&self) -> &[u8] {
        &self.security_buffer
    }
}

#[derive(Debug)]
#[repr(u16)]
pub enum SessionFlags {
    Empty = 0,
    Guest = 1,
    Anonymous = 2,
    Encrypt = 4,
}
impl SessionFlags {
    fn from_u16(u: u16) -> Option<Self> {
        match u {
            0 => Some(Self::Empty),
            1 => Some(Self::Guest),
            2 => Some(Self::Anonymous),
            4 => Some(Self::Encrypt),
            _ => None,
        }
    }
}
