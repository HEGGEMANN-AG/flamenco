use std::{borrow::Borrow, ops::Deref};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CRITICAL_SIZE: u32 = 0x0100_0000;

#[repr(transparent)]
pub struct NetBiosContent([u8]);

impl ToOwned for NetBiosContent {
    type Owned = OwnedNetBios;
    fn to_owned(&self) -> Self::Owned {
        OwnedNetBios::new(&self.0).unwrap()
    }
}
impl NetBiosContent {
    pub fn content(&self) -> &[u8] {
        &self.0
    }
    pub fn content_length(&self) -> u32 {
        self.0.len() as u32
    }
    pub async fn write_into_async<W: AsyncWrite + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), std::io::Error> {
        w.write_u32(self.content_length()).await?;
        w.write_all(self.content()).await?;
        Ok(())
    }
}
pub fn use_as_netbios_content(slice: &[u8]) -> Option<&NetBiosContent> {
    check_size(slice.len())
        .is_some()
        .then_some(unsafe { std::mem::transmute::<&[u8], &NetBiosContent>(slice) })
}

fn check_size(s: usize) -> Option<u32> {
    u32::try_from(s).ok().filter(|len| *len < CRITICAL_SIZE)
}

pub struct OwnedNetBios(Box<[u8]>);
impl OwnedNetBios {
    pub fn new(slice: &[u8]) -> Option<Self> {
        let length = check_size(slice.len())?;
        let be_len = length.to_be_bytes();
        assert_eq!(be_len[0], 0);
        let mut buf = Vec::with_capacity(4 + slice.len());
        buf.extend(be_len);
        buf.extend_from_slice(slice);
        Some(Self(buf.into_boxed_slice()))
    }
    pub async fn read_from_async<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, ReadError> {
        let mut bios_size = [0u8; 4];
        r.read_exact(&mut bios_size).await.map_err(ReadError::Io)?;
        let Some(size) = check_size(u32::from_be_bytes(bios_size) as usize) else {
            return Err(ReadError::InvalidLength);
        };
        let mut buf = vec![0; 4 + size as usize];
        buf[..4].copy_from_slice(&bios_size);
        r.read_exact(&mut buf[4..]).await.map_err(ReadError::Io)?;
        Ok(Self(buf.into_boxed_slice()))
    }
}
impl Borrow<NetBiosContent> for OwnedNetBios {
    fn borrow(&self) -> &NetBiosContent {
        self
    }
}
impl Deref for OwnedNetBios {
    type Target = NetBiosContent;
    fn deref(&self) -> &Self::Target {
        use_as_netbios_content(&self.0[4..]).expect("checked on creation")
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    InvalidLength,
}

#[cfg(test)]
mod test {
    #[test]
    fn test() {}
}
