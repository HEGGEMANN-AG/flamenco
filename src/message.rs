use std::{
    fmt::Debug,
    io::{Error as IoError, ErrorKind, Read, Write},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;

const STATUS_PENDING: u32 = 0x00000103;

use crate::header::{FLAG_SIGNED, SyncHeader202Incoming, SyncHeader202Outgoing};

/// Signature validation and netBIOS stuff should be happening here
pub fn read_202_message<R: Read>(
    mut r: R,
    validation: Validation,
) -> Result<(SyncHeader202Incoming, Box<[u8]>), ReadError> {
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
        0x0100_0000.. => return Err(ReadError::NetBIOS),
        size => size,
    };
    let mut header_bytes = [0u8; 64];
    r.read_exact(&mut header_bytes)
        .map_err(ReadError::Connection)?;
    let header = SyncHeader202Incoming::from_bytes(&header_bytes).unwrap();
    let message_body_size = (message_size - 64) as usize;
    let mut message_body = vec![0u8; message_body_size].into_boxed_slice();
    r.read_exact(&mut message_body)
        .map_err(ReadError::Connection)?;
    let is_signed = header.flags & FLAG_SIGNED != 0;
    match validation {
        Validation::Skip => Ok((header, message_body)),
        Validation::Key(key) => {
            if header.message_id != u64::MAX && header.status != STATUS_PENDING {
                if !is_signed {
                    Err(ReadError::NotSigned)
                } else if validate_signature(
                    &key,
                    &header.signature,
                    &mut header_bytes,
                    &message_body,
                ) {
                    Ok((header, message_body))
                } else {
                    Err(ReadError::InvalidSignature)
                }
            } else {
                Err(ReadError::InvalidlySignedMessage)
            }
        }
        Validation::ExpectNone if !is_signed && header.signature == [0u8; 16] => {
            Ok((header, message_body))
        }
        Validation::ExpectNone => Err(ReadError::InvalidlySignedMessage),
    }
}

#[derive(Debug, Default)]
pub enum Validation {
    Skip,
    #[default]
    ExpectNone,
    Key([u8; 16]),
}
impl From<Option<[u8; 16]>> for Validation {
    fn from(value: Option<[u8; 16]>) -> Self {
        match value {
            Some(key) => Self::Key(key),
            None => Self::ExpectNone,
        }
    }
}

fn validate_signature(
    key: &[u8; 16],
    sig: &[u8; 16],
    header_bytes: &mut [u8],
    body_bytes: &[u8],
) -> bool {
    header_bytes[48..64].fill(0);
    let mut hasher = Hmac::<Sha256>::new_from_slice(key).unwrap();
    hasher.update(header_bytes);
    hasher.update(body_bytes);
    hasher.finalize().into_bytes()[0..16] == *sig
}

#[derive(Debug)]
pub enum ReadError {
    NetBIOS,
    NotSigned,
    InvalidSignature,
    InvalidlySignedMessage,
    Connection(std::io::Error),
}

/// Sets the SIGNED flag depending on the signing key being provided
pub fn write_202_message<W: Write, M: MessageBody>(
    mut w: W,
    sign_with_key: Option<[u8; 16]>,
    mut header: SyncHeader202Outgoing,
    body: &M,
) -> Result<(), WriteError> {
    let mut buffer = Vec::with_capacity(64 + body.size_hint());
    if sign_with_key.is_some() {
        header.flags |= FLAG_SIGNED;
    }
    buffer.write_all(&header.to_bytes()).unwrap();
    body.write_to(&mut buffer).unwrap();
    match buffer.len() {
        0..=64 => unreachable!(),
        0x0100_0000.. => Err(WriteError::MessageTooLong),
        len => {
            if let Some(session_key) = sign_with_key {
                let mut hasher = Hmac::<Sha256>::new_from_slice(&session_key).unwrap();
                hasher.update(&buffer);
                let hash_result = hasher.finalize();
                buffer[48..64]
                    .copy_from_slice(hash_result.into_bytes().first_chunk::<16>().unwrap());
            }
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
