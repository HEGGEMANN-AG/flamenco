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
    io::{AsyncRead, AsyncWrite},
    sync::oneshot::Receiver,
};

use crate::{
    header::{FLAG_SIGNED, SyncHeader202Incoming, SyncHeader202Outgoing},
    message::{MessageBody, ReadError, WriteError},
    netbios::{OwnedNetBios, use_as_netbios_content},
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
    let netbios = OwnedNetBios::read_from_async(r).await?;
    let Some((header_bytes, message_body)) = netbios.content().split_first_chunk() else {
        return Err(ReadError::Connection(IoError::new(
            ErrorKind::UnexpectedEof,
            "Not enough data for header",
        )));
    };
    let header = SyncHeader202Incoming::from_bytes(header_bytes).unwrap();
    let content: Arc<[u8]> = Arc::from(message_body);
    let header = Arc::new(header);
    let signature_validator = Validator::new(header.clone(), validation_ctx_receiver, *header_bytes, content.clone());
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

fn buffer_and_sign_message<M: MessageBody>(
    sign_with_key: Option<[u8; 16]>,
    mut header: SyncHeader202Outgoing,
    body: &M,
    add_null: bool,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(64 + body.size_hint());
    if sign_with_key.is_some() {
        header.flags |= FLAG_SIGNED;
    }
    buffer.extend_from_slice(&header.to_bytes());
    body.write_to(&mut buffer);
    if add_null {
        buffer.push(0);
    }
    assert!(buffer.len() > 64);
    if let Some(session_key) = sign_with_key {
        let mut hasher = Hmac::<Sha256>::new_from_slice(&session_key).unwrap();
        hasher.update(&buffer);
        let hash_result = hasher.finalize().into_bytes();
        let hash_half = hash_result.first_chunk::<16>().unwrap();
        buffer[48..64].copy_from_slice(hash_half);
    }
    buffer
}

/// Sets the SIGNED flag depending on the signing key being provided
pub async fn write_202_message<W: AsyncWrite + Unpin, M: MessageBody>(
    w: &mut W,
    sign_with_key: Option<[u8; 16]>,
    header: SyncHeader202Outgoing,
    body: &M,
    add_null: bool,
) -> Result<(), WriteError> {
    let buf = buffer_and_sign_message(sign_with_key, header, body, add_null);
    let Some(netbios) = use_as_netbios_content(&buf) else {
        return Err(WriteError::MessageTooLong);
    };
    netbios.write_into_async(w).await.map_err(WriteError::Connection)
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
