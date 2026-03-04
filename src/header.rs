use std::num::NonZero;

use crate::{session::Session202, tree::TreeConnection};

const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

pub(crate) const FLAG_SIGNED: u32 = 0x08;

/// No status and signature, since they're not supported on the sender anyway
pub struct SyncHeader202Outgoing {
    pub command: Command202,
    pub credits: u16,
    pub flags: u32,
    pub next_command: Option<NonZero<u32>>,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
}
impl SyncHeader202Outgoing {
    pub fn from_session<Client>(session: &mut Session202<'_, Client>, command: Command202) -> Self {
        let message_id = session.connection.fetch_increment_message_id();
        Self {
            command,
            credits: 0,
            flags: if session.requires_signing() {
                FLAG_SIGNED
            } else {
                0
            },
            next_command: None,
            message_id,
            tree_id: 0,
            session_id: session.id,
        }
    }
    pub fn from_tree_con<Client>(
        tree_con: &mut TreeConnection<'_, '_, Client>,
        command: Command202,
    ) -> Self {
        let header = Self::from_session(tree_con.session_mut(), command);
        Self {
            tree_id: tree_con.id(),
            ..header
        }
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..4].copy_from_slice(&PROTOCOL_ID);
        bytes[4..6].copy_from_slice(&64u16.to_le_bytes());
        // credit charge and status is already 0
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.command.as_u16().to_le_bytes());
        bytes[14..16].copy_from_slice(&1u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.flags.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.next_command.map_or(0, |n| n.get()).to_le_bytes());
        bytes[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        bytes
    }
}

#[derive(Debug)]
pub struct SyncHeader202Incoming {
    /// ignored when sending
    pub status: u32,
    pub command: Command202,
    pub credits: u16,
    pub flags: u32,
    pub next_command: Option<NonZero<u32>>,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}
impl SyncHeader202Incoming {
    pub fn from_bytes(b: &[u8; 64]) -> Result<Self, Error> {
        if b[0..4] != PROTOCOL_ID {
            return Err(Error::InvalidProtocolID);
        };
        if u16::from_le_bytes(*b[4..6].as_array().unwrap()) != 64 {
            return Err(Error::InvalidSize);
        }
        // Ignore credit charge
        let status = u32::from_le_bytes(*b[8..12].as_array().unwrap());
        let command = u16::from_le_bytes(*b[12..14].as_array().unwrap());
        let command = Command202::from_code(command).ok_or(Error::InvalidCommand)?;
        let credits = u16::from_le_bytes(*b[14..16].as_array().unwrap());
        let flags = u32::from_le_bytes(*b[16..20].as_array().unwrap());
        let next_command = u32::from_le_bytes(*b[20..24].as_array().unwrap());
        let next_command = NonZero::new(next_command);
        let message_id = u64::from_le_bytes(*b[24..32].as_array().unwrap());
        let tree_id = u32::from_le_bytes(*b[36..40].as_array().unwrap());
        let session_id = u64::from_le_bytes(*b[40..48].as_array().unwrap());
        let signature: [u8; 16] = *b.last_chunk().unwrap();
        Ok(Self {
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidProtocolID,
    InvalidSize,
    InvalidCommand,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Command202 {
    Negotiate = 0x00,
    SessionSetup = 0x01,
    Logoff = 0x02,
    TreeConnect = 0x03,
    TreeDisconnect = 0x04,
    Create = 0x05,
    Close = 0x06,
    Flush = 0x07,
    Read = 0x08,
    Write = 0x09,
    Lock = 0x0A,
    IoCtl = 0x0B,
    Cancel = 0x0C,
    Echo = 0x0D,
    QueryDirectory = 0x0E,
    ChangeNotify = 0x0F,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}
impl Command202 {
    pub fn from_code(u: u16) -> Option<Self> {
        match u {
            0x00 => Some(Self::Negotiate),
            0x01 => Some(Self::SessionSetup),
            0x02 => Some(Self::Logoff),
            0x03 => Some(Self::TreeConnect),
            0x04 => Some(Self::TreeDisconnect),
            0x05 => Some(Self::Create),
            0x06 => Some(Self::Close),
            0x07 => Some(Self::Flush),
            0x08 => Some(Self::Read),
            0x09 => Some(Self::Write),
            0x0A => Some(Self::Lock),
            0x0B => Some(Self::IoCtl),
            0x0C => Some(Self::Cancel),
            0x0D => Some(Self::Echo),
            0x0E => Some(Self::QueryDirectory),
            0x0F => Some(Self::ChangeNotify),
            0x10 => Some(Self::QueryInfo),
            0x11 => Some(Self::SetInfo),
            0x12 => Some(Self::OplockBreak),
            _ => None,
        }
    }
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Negotiate => 0x00,
            Self::SessionSetup => 0x01,
            Self::Logoff => 0x02,
            Self::TreeConnect => 0x03,
            Self::TreeDisconnect => 0x04,
            Self::Create => 0x05,
            Self::Close => 0x06,
            Self::Flush => 0x07,
            Self::Read => 0x08,
            Self::Write => 0x09,
            Self::Lock => 0x0A,
            Self::IoCtl => 0x0B,
            Self::Cancel => 0x0C,
            Self::Echo => 0x0D,
            Self::QueryDirectory => 0x0E,
            Self::ChangeNotify => 0x0F,
            Self::QueryInfo => 0x10,
            Self::SetInfo => 0x11,
            Self::OplockBreak => 0x12,
        }
    }
}
