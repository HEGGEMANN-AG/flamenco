use std::{fmt::Debug, ops::BitOr};

#[derive(Clone, Copy)]
pub union AccessMask {
    file_pipe_printer: FilePipePrinterAccess,
    directory: DirectoryAccess,
}
impl Debug for AccessMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:b}", self.as_directory().0)
    }
}
impl AccessMask {
    pub fn as_file_pipe_printer(self) -> FilePipePrinterAccess {
        unsafe { self.file_pipe_printer }
    }
    pub fn as_directory(self) -> DirectoryAccess {
        unsafe { self.directory }
    }
    pub fn new(u: u32) -> Self {
        Self {
            file_pipe_printer: FilePipePrinterAccess(u),
        }
    }
    pub fn as_u32(self) -> u32 {
        self.as_directory().0
    }
}

#[derive(Clone, Copy, Default)]
pub struct FilePipePrinterAccess(u32);
impl FilePipePrinterAccess {
    pub const FILE_READ_DATA: Self = Self(0x01);
    pub const FILE_WRITE_DATA: Self = Self(0x02);
    pub const FILE_APPEND_DATA: Self = Self(0x04);
    pub const FILE_READ_EA: Self = Self(0x08);
    pub const FILE_WRITE_EA: Self = Self(0x10);
    pub const FILE_DELETE_CHILD: Self = Self(0x40);
    pub const FILE_EXECUTE: Self = Self(0x20);
    pub const FILE_READ_ATTRIBUTES: Self = Self(0x80);
    pub const FILE_WRITE_ATTRIBUTES: Self = Self(0x100);
    pub const DELETE: Self = Self(0x10000);
    pub const READ_CONTROL: Self = Self(0x20000);
    pub const WRITE_DAC: Self = Self(0x40000);
    pub const WRITE_OWNER: Self = Self(0x80000);
    pub const SYNCHRONIZE: Self = Self(0x100000);
    pub const ACCESS_SYSTEM_SECURITY: Self = Self(0x1000000);
    pub const MAXIMUM_ALLOWED: Self = Self(0x2000000);
    pub const GENERIC_ALL: Self = Self(0x10000000);
    pub const GENERIC_EXECUTE: Self = Self(0x20000000);
    pub const GENERIC_WRITE: Self = Self(0x40000000);
    pub const GENERIC_READ: Self = Self(0x80000000);

    pub fn empty() -> Self {
        Default::default()
    }
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub fn from_u32(u: u32) -> Self {
        Self(u)
    }
}
impl BitOr for FilePipePrinterAccess {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Default)]
pub struct DirectoryAccess(u32);
impl DirectoryAccess {
    pub const FILE_LIST_DIRECTORY: Self = Self(0x01);
    pub const FILE_ADD_FILE: Self = Self(0x02);
    pub const FILE_ADD_SUBDIRECTORY: Self = Self(0x04);
    pub const FILE_READ_EA: Self = Self(0x08);
    pub const FILE_WRITE_EA: Self = Self(0x10);
    pub const FILE_TRAVERSE: Self = Self(0x20);
    pub const FILE_DELETE_CHILD: Self = Self(0x40);
    pub const FILE_READ_ATTRIBUTES: Self = Self(0x80);
    pub const FILE_WRITE_ATTRIBUTES: Self = Self(0x100);
    pub const DELETE: Self = Self(0x10000);
    pub const READ_CONTROL: Self = Self(0x20000);
    pub const WRITE_DAC: Self = Self(0x40000);
    pub const WRITE_OWNER: Self = Self(0x80000);
    pub const SYNCHRONIZE: Self = Self(0x100000);
    pub const ACCESS_SYSTEM_SECURITY: Self = Self(0x1000000);
    pub const MAXIMUM_ALLOWED: Self = Self(0x2000000);
    pub const GENERIC_ALL: Self = Self(0x10000000);
    pub const GENERIC_EXECUTE: Self = Self(0x20000000);
    pub const GENERIC_WRITE: Self = Self(0x40000000);
    pub const GENERIC_READ: Self = Self(0x80000000);
    pub fn empty() -> Self {
        Default::default()
    }
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    pub fn from_u32(u: u32) -> Self {
        Self(u)
    }
}
