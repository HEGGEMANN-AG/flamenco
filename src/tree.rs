use std::io::{ErrorKind, Read, Write};

use crate::{Smb2ClientMessage, access::AccessMask, byteorder::LittleEndian};

pub struct TreeConnectRequest {
    share_path: Vec<u8>,
}
impl TreeConnectRequest {
    const SIZE_ON_WIRE: u16 = 9;
    pub fn new(share_path: &str) -> Self {
        let share_path = share_path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        TreeConnectRequest { share_path }
    }

    fn write_to<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        Self::SIZE_ON_WIRE.write_le(&mut writer)?;
        0u16.write_le(&mut writer)?;
        (64u16 + 8u16).write_le(&mut writer)?;
        (self.share_path.len() as u16).write_le(&mut writer)?;
        writer.write_all(self.share_path.as_slice())?;
        Ok(())
    }
}
impl Smb2ClientMessage for TreeConnectRequest {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.write_to(writer)
    }
    fn size_hint(&self) -> usize {
        17
    }
}

#[derive(Debug)]
pub struct TreeConnectResponse {
    pub share_type: ShareType,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: AccessMask,
}
impl TreeConnectResponse {
    pub fn read_from<R: Read>(mut r: R) -> std::io::Result<Self> {
        let structure_size = u16::read_le(&mut r)?;
        assert_eq!(structure_size, 16);
        let mut share_type = 0u8;
        r.read_exact(std::slice::from_mut(&mut share_type))?;
        let share_type = ShareType::from_u8(share_type)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "invalid share type"))?;
        let mut _reserved = 0u8;
        r.read_exact(std::slice::from_mut(&mut _reserved))?;
        let share_flags = u32::read_le(&mut r)?;
        let capabilities = u32::read_le(&mut r)?;
        let maximal_access = AccessMask::new(u32::read_le(&mut r)?);
        Ok(Self {
            share_type,
            share_flags,
            capabilities,
            maximal_access,
        })
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum ShareType {
    Disk = 1,
    Pipe = 2,
    Printer = 3,
}
impl ShareType {
    pub fn from_u8(u: u8) -> Option<Self> {
        match u {
            1 => Some(Self::Disk),
            2 => Some(Self::Pipe),
            3 => Some(Self::Printer),
            _ => None,
        }
    }
}
