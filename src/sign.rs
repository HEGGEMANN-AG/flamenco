use crate::header::{FLAG_SIGNED, SyncHeader202Incoming};

#[derive(Debug)]
pub enum ValidationError {
    InvalidSignature,
    ChannelClosed,
    SigningRequiredButMissing,
}

pub struct ValidationContext {
    pub(crate) key: Option<[u8; 16]>,
    pub(crate) requires_signing: bool,
}
impl std::fmt::Debug for ValidationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationContext")
            .field(
                "key",
                &if self.key.is_some() {
                    "Some(REDACTED)"
                } else {
                    "None"
                },
            )
            .field("requires_signing", &self.requires_signing)
            .finish()
    }
}

pub enum ValidationDecision {
    MustVerify,
    Skip,
}

const STATUS_PENDING: u32 = 0x00000103;

pub fn should_enforce_signature_validation(
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SecurityMode {
    None,
    SigningEnabled,
    SigningRequired,
}
impl SecurityMode {
    pub fn from_value(i: u16) -> Self {
        if i & 0x02 != 0 {
            Self::SigningRequired
        } else if i & 0x01 != 0 {
            Self::SigningEnabled
        } else {
            Self::None
        }
    }
    pub fn to_value(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::SigningEnabled => 0x01,
            Self::SigningRequired => 0x02,
        }
    }
}
