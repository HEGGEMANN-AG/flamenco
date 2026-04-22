use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

#[derive(Clone, Copy, Debug, Default)]
pub struct FileAttributes(u32);
impl FileAttributes {
    pub const EMPTY: Self = Self(0x00);
    pub const READ_ONLY: Self = Self(0x01);
    pub const HIDDEN: Self = Self(0x02);
    pub const SYSTEM: Self = Self(0x04);
    pub const DIRECTORY: Self = Self(0x10);
    pub const ARCHIVE: Self = Self(0x20);
    pub const NORMAL: Self = Self(0x80);
    pub const TEMPORARY: Self = Self(0x100);
    pub const SPARSE: Self = Self(0x200);
    pub const REPARSE_POINT: Self = Self(0x400);
    pub const COMPRESSED: Self = Self(0x800);
    pub const OFFLINE: Self = Self(0x1000);
    pub const NOT_CONTENT_INDEXED: Self = Self(0x2000);
    pub const ENCRYPTED: Self = Self(0x4000);
    pub const INTEGRITY_STREAM: Self = Self(0x8000);
    pub const fn to_int(self) -> u32 {
        self.0
    }
    pub const fn from_int(u: u32) -> Self {
        Self(u)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}
impl BitOr<Self> for FileAttributes {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl BitAnd<Self> for FileAttributes {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}
impl BitOrAssign for FileAttributes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}
impl BitAndAssign for FileAttributes {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0
    }
}
