use std::io::ErrorKind;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CRITICAL_SIZE: u32 = 0x0100_0000;

pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    f: impl FnOnce(&mut Vec<u8>),
) -> Result<(), std::io::Error> {
    let mut v = Vec::new();
    f(&mut v);
    let length = u32::try_from(v.len()).map_err(|_| message_too_long())?;
    if length >= CRITICAL_SIZE {
        return Err(message_too_long());
    }
    w.write_u32(length).await?;
    w.write_all(&v).await?;
    Ok(())
}

fn message_too_long() -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, "message too long")
}

pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<impl AsRef<[u8]>, std::io::Error> {
    let length = r.read_u32().await?;
    if length >= CRITICAL_SIZE {
        return Err(message_too_long());
    }
    let mut buf = vec![0; length as usize].into_boxed_slice();
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
