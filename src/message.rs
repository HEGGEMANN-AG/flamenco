use std::io::{ErrorKind, Read};

use crate::header::SyncHeader202;

pub fn read_202_message<R: Read>(mut r: R) -> std::io::Result<(SyncHeader202, Box<[u8]>)> {
    let mut bios_size = [0u8; 4];
    r.read_exact(&mut bios_size)?;
    let message_size = match u32::from_be_bytes(bios_size) {
        0..64 => {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "Not enough data for header",
            ));
        }
        0x0100_0000.. => panic!("Invalid header: no leading zero"),
        size => size,
    };
    let mut header_bytes = [0u8; 64];
    r.read_exact(&mut header_bytes)?;
    let header = SyncHeader202::from_bytes(&header_bytes).unwrap();
    let message_body_size = (message_size - 64) as usize;
    let mut message_body = vec![0u8; message_body_size].into_boxed_slice();
    r.read_exact(&mut message_body)?;
    Ok((header, message_body))
}
