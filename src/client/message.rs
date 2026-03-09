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

use crate::{
    header::{FLAG_SIGNED, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, WriteError},
    sign::{ValidationContext, ValidationError},
};

#[derive(Debug)]
pub struct IncomingMessage {
    pub header: Arc<SyncHeader202Incoming>,
    pub content: Arc<[u8]>,
    pub signature_validator: Validator,
}

pub async fn read_202_message<R: AsyncRead + Unpin>(
    r: &mut R,
    validation_ctx_receiver: Receiver<ValidationContext>,
) -> Result<IncomingMessage, ReadError> {
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
    let header = Arc::new(header);
    let signature_validator =
        Validator::new(header.clone(), validation_ctx_receiver, header_bytes, body);
    Ok(IncomingMessage {
        header,
        content,
        signature_validator,
    })
}

#[derive(Debug)]
pub struct Validator {
    header_bytes: [u8; 64],
    parsed_header: Arc<SyncHeader202Incoming>,
    body: Arc<[u8]>,
    signature: [u8; 16],

    validation_ctx: Receiver<ValidationContext>,
}
impl Validator {
    fn new(
        header: Arc<SyncHeader202Incoming>,
        validation_ctx: Receiver<ValidationContext>,
        header_bytes: [u8; 64],
        body: Arc<[u8]>,
    ) -> Self {
        let signature = header.signature;
        Self {
            parsed_header: header,
            header_bytes,
            body,
            signature,
            validation_ctx,
        }
    }
}
impl Future for Validator {
    type Output = Result<(), ValidationError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let sig = self.signature;
        let this = &mut *self;
        let header_bytes = &mut this.header_bytes;
        let header = this.parsed_header.as_ref();
        let body = &this.body;

        match Pin::new(&mut this.validation_ctx).poll(cx) {
            Poll::Ready(Ok(ctx)) => {
                let Some(key) = ctx.key else {
                    return Poll::Ready(Ok(()));
                };

                match should_enforce_signature_validation(header, ctx.requires_signing) {
                    Ok(ValidationDecision::Skip) => Poll::Ready(Ok(())),
                    Ok(ValidationDecision::MustVerify) => {
                        Poll::Ready(Self::validate_signature(key, sig, header_bytes, body))
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(ValidationError::ChannelClosed)),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Validator {
    fn validate_signature(
        key: [u8; 16],
        sig: [u8; 16],
        header_bytes: &mut [u8],
        body_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        header_bytes[48..64].fill(0);
        let mut hasher = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hasher.update(header_bytes);
        hasher.update(body_bytes);
        if hasher.finalize().into_bytes()[0..16] == sig {
            Ok(())
        } else {
            Err(ValidationError::InvalidSignature)
        }
    }
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
    body.write_to(&mut buffer);
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

#[derive(Debug)]
enum ValidationDecision {
    MustVerify,
    Skip,
}

const STATUS_PENDING: u32 = 0x00000103;

fn should_enforce_signature_validation(
    header: &SyncHeader202Incoming,
    session_requires_signing: bool,
) -> Result<ValidationDecision, ValidationError> {
    let is_signed = header.flags & FLAG_SIGNED != 0;
    let is_async = header.message_id == u64::MAX;
    let is_interim = is_async || header.status == STATUS_PENDING;

    // Voluntary signing is always verified
    if is_signed {
        return Ok(ValidationDecision::MustVerify);
    }

    if !session_requires_signing || is_interim {
        return Ok(ValidationDecision::Skip);
    }

    Err(ValidationError::SigningRequiredButMissing)
}
