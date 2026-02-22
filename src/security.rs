use std::{fmt::Debug, ops::BitOr};

#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityMode16(u16);
impl SecurityMode16 {
    pub const SIGNING_ENABLED: Self = Self(0b01);
    pub const SIGNING_REQUIRED: Self = Self(0b10);
    pub fn signing_enabled(self) -> bool {
        self.contains(Self::SIGNING_ENABLED)
    }
    pub fn signing_required(self) -> bool {
        self.contains(Self::SIGNING_REQUIRED)
    }
    pub fn as_u16(self) -> u16 {
        self.0
    }
    pub fn from_u16(u: u16) -> Option<Self> {
        (u <= 0b11).then_some(Self(u))
    }
    pub fn empty() -> Self {
        Self::default()
    }
    fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}
impl BitOr for SecurityMode16 {
    type Output = SecurityMode16;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityMode8(u8);
impl SecurityMode8 {
    pub const SIGNING_ENABLED: Self = Self(0b01);
    pub const SIGNING_REQUIRED: Self = Self(0b10);
    pub fn signing_enabled(self) -> bool {
        self.contains(Self::SIGNING_ENABLED)
    }
    pub fn signing_required(self) -> bool {
        self.contains(Self::SIGNING_REQUIRED)
    }
    pub fn as_u8(self) -> u8 {
        self.0
    }
    pub fn from_u16(u: u8) -> Option<Self> {
        (u <= 0b11).then_some(Self(u))
    }
    pub fn empty() -> Self {
        Self::default()
    }
    fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}
impl BitOr for SecurityMode8 {
    type Output = SecurityMode8;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
