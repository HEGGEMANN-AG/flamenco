use std::fmt::Debug;

#[derive(Debug)]
pub enum ReadError {
    NetBIOS,
    InvalidlySignedMessage,
    Connection(std::io::Error),
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
