use std::fmt::Debug;

use tokio::io::AsyncWrite;

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
    type Err: Debug;
    async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), Self::Err>;
    fn size_hint(&self) -> usize {
        0
    }
}
