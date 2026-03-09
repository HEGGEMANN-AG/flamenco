use std::io::Read;

pub mod client;
mod error;
pub mod file;
mod header;
mod message;
mod negotiate;
mod netbios;
pub mod session;
mod share_name;
mod sign;
pub mod tree;

fn to_wide(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<_>>()
}

pub(crate) trait ReadIntLe: Read {
    fn read_u16_le(&mut self) -> std::io::Result<u16> {
        let mut arr = [0u8; 2];
        self.read_exact(&mut arr)?;
        Ok(u16::from_le_bytes(arr))
    }
    fn read_u32_le(&mut self) -> std::io::Result<u32> {
        let mut arr = [0u8; 4];
        self.read_exact(&mut arr)?;
        Ok(u32::from_le_bytes(arr))
    }
    fn read_u64_le(&mut self) -> std::io::Result<u64> {
        let mut arr = [0u8; 8];
        self.read_exact(&mut arr)?;
        Ok(u64::from_le_bytes(arr))
    }
}
impl<R: Read> ReadIntLe for R {}
