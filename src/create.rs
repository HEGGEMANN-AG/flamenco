use std::io::{Read, Write};

use crate::{Smb2ClientMessage, access::AccessMask, byteorder::LittleEndian, file::FileId};

pub struct CreateRequest {
    pub oplock_level: OplockLevel,
    pub desired_access: AccessMask,
    pub share_access: ShareAccess,
    pub create_disposition: CreateDisposition,
    pub file_name: Option<String>,
}
impl CreateRequest {
    const SIZE_ON_WIRE: u16 = 57;
    fn write_to<W: Write>(&self, mut w: W) -> std::io::Result<()> {
        // size
        Self::SIZE_ON_WIRE.write_le(&mut w)?;
        w.write_all(&[0])?;
        // Oplock level
        w.write_all(&[self.oplock_level as u8])?;
        // impersonation level
        0u32.write_le(&mut w)?;
        // smbcreateflags
        0u64.write_le(&mut w)?;
        // reserved
        0u64.write_le(&mut w)?;
        // desired access
        self.desired_access.as_u32().write_le(&mut w)?;
        // file attributes
        // -----TODO------
        0u32.write_le(&mut w)?;
        // Share access
        self.share_access.0.write_le(&mut w)?;
        (self.create_disposition as u32).write_le(&mut w)?;
        // create options
        0u32.write_le(&mut w)?;
        let name = self
            .file_name
            .as_ref()
            .map(|s| s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>());
        // name offset TODO
        (64u16 + 56u16).write_le(&mut w)?;
        // name length TODO
        name.as_ref()
            .map(|s| s.len() as u16)
            .unwrap_or_default()
            .write_le(&mut w)?;
        // create contexts offset
        0u32.write_le(&mut w)?;
        // create context length
        0u32.write_le(&mut w)?;
        if let Some(name) = name {
            w.write_all(&name)?;
        }
        Ok(())
    }
}
impl Smb2ClientMessage for CreateRequest {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.write_to(writer)
    }

    fn size_hint(&self) -> usize {
        56
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum OplockLevel {
    None = 0,
    LevelII = 1,
    LevelExclusive = 8,
    LevelBatch = 9,
    LevelLease = 0xFF,
}
impl OplockLevel {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::LevelII),
            8 => Some(Self::LevelExclusive),
            9 => Some(Self::LevelBatch),
            0xFF => Some(Self::LevelLease),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct ShareAccess(u32);

#[derive(Clone, Copy, Debug, Default)]
#[repr(u32)]
pub enum CreateDisposition {
    Supersede = 0x0,
    #[default]
    Open = 0x1,
    Create = 0x2,
    OpenIf = 0x3,
    Overwrite = 0x4,
    OverwriteIf = 0x5,
}

#[derive(Debug)]
pub struct CreateResponse {
    pub oplock_level: OplockLevel,
    pub create_action: CreateAction,
    pub allocation_size: u64,
    pub size: u64,
    pub file_id: FileId,
}
impl CreateResponse {
    pub fn read_from<R: Read>(mut r: R) -> std::io::Result<Self> {
        let structure_size = u16::read_le(&mut r)?;
        assert_eq!(structure_size, 89);
        let mut oplock_byte = 0;
        r.read_exact(std::slice::from_mut(&mut oplock_byte))?;
        let oplock_level = OplockLevel::from_byte(oplock_byte).unwrap();
        let mut _reserved = 0;
        r.read_exact(std::slice::from_mut(&mut _reserved))?;
        let create_action = u32::read_le(&mut r)?;
        let create_action = CreateAction::new(create_action).unwrap();
        let _creation_time = u64::read_le(&mut r)?;
        let _last_access_time = u64::read_le(&mut r)?;
        let _last_write_time = u64::read_le(&mut r)?;
        let _change_time = u64::read_le(&mut r)?;
        let allocation_size = u64::read_le(&mut r)?;
        let size = u64::read_le(&mut r)?;
        let _file_attributes = u32::read_le(&mut r)?;
        let _reserved2 = u32::read_le(&mut r)?;
        let persistent = u64::read_le(&mut r)?;
        let volatile = u64::read_le(&mut r)?;
        let file_id = FileId::new(persistent, volatile);
        let _create_contexts_offset = u32::read_le(&mut r)?;
        let _create_contexts_length = u32::read_le(&mut r)?;

        if _create_contexts_offset != 0 {
            let mut _padding = vec![0; dbg!(_create_contexts_offset) as usize - 64 + 88];
            r.read_exact(&mut _padding)?;
            let mut _context = vec![0; _create_contexts_length as usize];
            r.read_exact(&mut _context)?;
        }

        Ok(Self {
            oplock_level,
            create_action,
            allocation_size,
            size,
            file_id,
        })
    }
}

#[derive(Debug)]
pub enum CreateAction {
    Superseded,
    Opened,
    Created,
    Overwritten,
}
impl CreateAction {
    fn new(val: u32) -> Option<Self> {
        match val {
            0x00 => Some(Self::Superseded),
            0x01 => Some(Self::Opened),
            0x02 => Some(Self::Created),
            0x03 => Some(Self::Overwritten),
            _ => None,
        }
    }
}
