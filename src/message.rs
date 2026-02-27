use std::{
    fmt::Debug,
    io::{Error as IoError, ErrorKind, Read, Write},
};

use crate::header::SyncHeader202;

/// Signature validation and netBIOS stuff should be happening here
pub fn read_202_message<R: Read>(mut r: R) -> Result<(SyncHeader202, Box<[u8]>), ReadError> {
    let mut bios_size = [0u8; 4];
    r.read_exact(&mut bios_size)
        .map_err(ReadError::Connection)?;
    let message_size = match u32::from_be_bytes(bios_size) {
        0..64 => {
            return Err(ReadError::Connection(IoError::new(
                ErrorKind::UnexpectedEof,
                "Not enough data for header",
            )));
        }
        0x0100_0000.. => panic!("Invalid header: no leading zero"),
        size => size,
    };
    let mut header_bytes = [0u8; 64];
    r.read_exact(&mut header_bytes)
        .map_err(ReadError::Connection)?;
    let header = SyncHeader202::from_bytes(&header_bytes).unwrap();
    let message_body_size = (message_size - 64) as usize;
    let mut message_body = vec![0u8; message_body_size].into_boxed_slice();
    r.read_exact(&mut message_body)
        .map_err(ReadError::Connection)?;
    Ok((header, message_body))
}

#[derive(Debug)]
pub enum ReadError {
    Connection(std::io::Error),
}

pub fn write_202_message<W: Write, M: MessageBody>(
    mut w: W,
    header: &SyncHeader202,
    body: &M,
) -> Result<(), WriteError> {
    let mut buffer = Vec::with_capacity(64 + body.size_hint());
    buffer.write_all(&header.to_bytes()).unwrap();
    body.write_to(&mut buffer).unwrap();
    match buffer.len() {
        0..=64 => unreachable!(),
        0x0100_0000.. => Err(WriteError::MessageTooLong),
        len => {
            w.write_all(&(len as u32).to_be_bytes())
                .map_err(WriteError::Connection)?;
            w.write_all(&buffer).map_err(WriteError::Connection)?;
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum WriteError {
    Connection(std::io::Error),
    MessageTooLong,
}

pub(crate) trait MessageBody {
    type Err: Debug;
    fn write_to<W: Write>(&self, w: W) -> Result<(), Self::Err>;
    fn size_hint(&self) -> usize {
        0
    }
}
