use std::{
    io::{ErrorKind, Read, Write},
    num::NonZero,
};

use crate::{byteorder::LittleEndian, command::Command};

#[derive(Debug)]
pub struct Smb2SyncHeader {
    pub credit_charge: u16,
    pub status: u32,
    pub command: Command,
    pub credit_request_or_response: u16,
    pub flags: Flags,
    pub next_command: Option<NonZero<u32>>,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}
impl Smb2SyncHeader {
    const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

    pub(crate) const SIZE_ON_WIRE: u16 = 64;
    pub fn write_to<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&Self::PROTOCOL_ID)?;
        Self::SIZE_ON_WIRE.write_le(&mut writer)?;
        self.credit_charge.write_le(&mut writer)?;
        self.status.write_le(&mut writer)?;
        (self.command as u16).write_le(&mut writer)?;
        self.credit_request_or_response.write_le(&mut writer)?;
        self.flags.0.write_le(&mut writer)?;
        self.next_command.map_or(0, NonZero::get).write_le(&mut writer)?;
        self.message_id.write_le(&mut writer)?;
        0u32.write_le(&mut writer)?;
        self.tree_id.write_le(&mut writer)?;
        self.session_id.write_le(&mut writer)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
    pub fn read_from<R: Read>(mut read: &mut R) -> std::io::Result<Self> {
        let mut protocol_id = [0u8; 4];
        read.read_exact(&mut protocol_id)?;
        assert_eq!(protocol_id, Self::PROTOCOL_ID);

        let structure_size = u16::read_le(&mut read)?;
        assert_eq!(64, structure_size);

        let credit_charge = u16::read_le(&mut read)?;
        let status = u32::read_le(&mut read)?;
        let command = Command::from_u16(u16::read_le(&mut read)?)
            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "invalid command"))?;
        let credit_request_or_response = u16::read_le(&mut read)?;
        let flags = u32::read_le(&mut read)?;
        let next_command = NonZero::new(u32::read_le(&mut read)?);

        let message_id = u64::read_le(&mut read)?;
        let _reserved = u32::read_le(&mut read)?;
        let tree_id = u32::read_le(&mut read)?;
        let session_id = u64::read_le(&mut read)?;
        let mut signature = [0u8; 16];
        read.read_exact(&mut signature)?;

        Ok(Self {
            credit_charge,
            status,
            command,
            credit_request_or_response,
            flags: Flags(flags),
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Flags(u32);
impl Flags {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn contains(self, flag: Flags) -> bool {
        self.0 & flag.0 != 0
    }
}
pub const FLAG_SIGNED: Flags = Flags(0x8);
