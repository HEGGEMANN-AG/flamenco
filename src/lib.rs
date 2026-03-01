use std::io::Read;

pub mod client;
mod error;
pub mod file;
mod header;
mod message;
mod negotiate;
mod session;
mod share_name;
mod sign;
mod tree;

trait ReadLe: Read {
    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}
impl<T: Read> ReadLe for T {}
