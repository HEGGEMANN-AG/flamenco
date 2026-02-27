use std::io::Read;

pub mod client;
mod error;
mod header;
mod message;
mod negotiate;

trait ReadLe: Read {
    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
}
impl<T: Read> ReadLe for T {}
