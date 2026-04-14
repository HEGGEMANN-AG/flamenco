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
