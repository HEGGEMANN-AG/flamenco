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
