use std::{
    future::Future,
    io::{Error as IoError, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot::Receiver,
};

const STATUS_PENDING: u32 = 0x00000103;

use crate::{
    header::{FLAG_SIGNED, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, WriteError},
};

pub struct UnparsedMessage {
    pub header: SyncHeader202Incoming,
    pub content: Arc<[u8]>,
    pub signature_validator: Validator,
}

/// Signature validation and netBIOS stuff should be happening here
pub async fn read_202_message<R: AsyncRead + Unpin>(
    r: &mut R,
    incoming_key: Receiver<Option<[u8; 16]>>,
) -> Result<UnparsedMessage, ReadError> {
    let mut bios_size = [0u8; 4];
    r.read_exact(&mut bios_size)
        .await
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
        .await
        .map_err(ReadError::Connection)?;
    let header = SyncHeader202Incoming::from_bytes(&header_bytes).unwrap();
    let message_body_size = (message_size - 64) as usize;
    let mut message_body = vec![0u8; message_body_size];
    r.read_exact(&mut message_body)
        .await
        .map_err(ReadError::Connection)?;
    let content: Arc<[u8]> = Arc::from(message_body);
    let body = content.clone();
    let signature_validator = Validator::new(&header, incoming_key, header_bytes, body);
    Ok(UnparsedMessage {
        header,
        content,
        signature_validator,
    })
}

pub struct Validator {
    header_bytes: [u8; 64],
    body: Arc<[u8]>,
    message_id: u64,
    signature: [u8; 16],
    flags: u32,
    status: u32,

    incoming_key: Receiver<Option<[u8; 16]>>,
}
impl Validator {
    fn new(
        header: &SyncHeader202Incoming,
        incoming_key: Receiver<Option<[u8; 16]>>,
        header_bytes: [u8; 64],
        body: Arc<[u8]>,
    ) -> Self {
        Self {
            header_bytes,
            body,
            message_id: header.message_id,
            signature: header.signature,
            flags: header.flags,
            status: header.status,
            incoming_key,
        }
    }
}
impl Future for Validator {
    type Output = Result<(), ValidationError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let sig = self.signature;
        let mid = self.message_id;
        let flags = self.flags;
        let status = self.status;
        let this = &mut *self;
        let incoming_key = &mut this.incoming_key;
        let header_bytes = &mut this.header_bytes;
        let body = &this.body;
        match Pin::new(incoming_key).poll(cx) {
            Poll::Ready(Ok(key)) => Poll::Ready(match key {
                None => Ok(()),
                Some(key) => {
                    Self::validate_to_error(key, sig, mid, flags, status, header_bytes, body)
                }
            }),
            Poll::Ready(Err(_)) => Poll::Ready(Err(ValidationError::ChannelClosed)),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Validator {
    fn validate_to_error(
        key: [u8; 16],
        signature: [u8; 16],
        message_id: u64,
        flags: u32,
        status: u32,
        header_bytes: &mut [u8],
        body_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        let is_signed = flags & FLAG_SIGNED != 0;
        if message_id != u64::MAX && status != STATUS_PENDING {
            if !is_signed {
                Err(ValidationError::NotSigned)
            } else if Self::validate_signature(key, signature, header_bytes, body_bytes) {
                Ok(())
            } else {
                Err(ValidationError::InvalidSignature)
            }
        } else {
            Ok(())
        }
    }
    fn validate_signature(
        key: [u8; 16],
        sig: [u8; 16],
        header_bytes: &mut [u8],
        body_bytes: &[u8],
    ) -> bool {
        header_bytes[48..64].fill(0);
        let mut hasher = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hasher.update(header_bytes);
        hasher.update(body_bytes);
        hasher.finalize().into_bytes()[0..16] == sig
    }
}

pub enum ValidationError {
    NotSigned,
    InvalidSignature,
    ChannelClosed,
}

/// Sets the SIGNED flag depending on the signing key being provided
pub async fn write_202_message<W: AsyncWrite + Unpin, M: MessageBody>(
    w: &mut W,
    sign_with_key: Option<[u8; 16]>,
    mut header: SyncHeader202Outgoing,
    body: &M,
    add_null: bool,
) -> Result<(), WriteError> {
    let mut buffer = Vec::with_capacity(64 + body.size_hint());
    if sign_with_key.is_some() {
        header.flags |= FLAG_SIGNED;
    }
    buffer.write_all(&header.to_bytes()).await.unwrap();
    body.write_to(&mut buffer).await.unwrap();
    if add_null {
        buffer.push(0);
    }
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
                .await
                .map_err(WriteError::Connection)?;
            w.write_all(&buffer).await.map_err(WriteError::Connection)?;
            Ok(())
        }
    }
}
