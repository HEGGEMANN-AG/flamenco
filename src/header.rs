use std::num::NonZero;

const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

#[derive(Debug)]
struct SyncHeader202 {
    command: Command,
    credits: u16,
    flags: u32,
    next_command: Option<NonZero<u32>>,
    message_id: u64,
    tree_id: u32,
    session_id: u64,
    signature: [u8; 16],
}
impl SyncHeader202 {
    pub fn from_bytes(b: &[u8; 64]) -> Result<Self, Error> {
        if b[0..4] != PROTOCOL_ID {
            return Err(Error::InvalidProtocolID);
        };
        if u16::from_be_bytes(*b[4..6].as_array().unwrap()) != 64 {
            return Err(Error::InvalidSize);
        }
        // Ignore credit charge and status
        let command = u16::from_be_bytes(*b[12..14].as_array().unwrap());
        let command = Command::from_code(command).ok_or(Error::InvalidCommand)?;
        let credits = u16::from_be_bytes(*b[14..16].as_array().unwrap());
        let flags = u32::from_be_bytes(*b[16..20].as_array().unwrap());
        let next_command = u32::from_be_bytes(*b[20..24].as_array().unwrap());
        let next_command = NonZero::new(next_command);
        let message_id = u64::from_be_bytes(*b[24..32].as_array().unwrap());
        let tree_id = u32::from_be_bytes(*b[36..40].as_array().unwrap());
        let session_id = u64::from_be_bytes(*b[40..48].as_array().unwrap());
        let signature: [u8; 16] = *b[48..64].as_array().unwrap();
        Ok(Self {
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

#[derive(Clone, Copy, Debug)]
pub enum Command {
    Negotiate = 0x00,
    SessionSetup = 0x01,
    Logoff = 0x02,
}
impl Command {
    pub fn from_code(u: u16) -> Option<Self> {
        match u {
            0x00 => Some(Self::Negotiate),
            0x01 => Some(Self::SessionSetup),
            0x02 => Some(Self::Logoff),
            0x03..=0x13 => todo!("unimplemented command"),
            _ => None,
        }
    }
}
