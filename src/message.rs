use crate::netbios::ReadError as NetBIOSError;
use std::fmt::Debug;

#[derive(Debug)]
pub enum ReadError {
    InvalidNetbiosLength,
    InvalidlySignedMessage,
    Connection(std::io::Error),
}
impl From<NetBIOSError> for ReadError {
    fn from(value: NetBIOSError) -> Self {
        match value {
            NetBIOSError::Io(error) => Self::Connection(error),
            NetBIOSError::InvalidLength => Self::InvalidNetbiosLength,
        }
    }
}

#[derive(Debug)]
pub enum WriteError {
    Connection(std::io::Error),
    MessageTooLong,
}

pub(crate) trait MessageBody {
    fn write_to(&self, w: &mut Vec<u8>);
    fn size_hint(&self) -> usize {
        0
    }
}
