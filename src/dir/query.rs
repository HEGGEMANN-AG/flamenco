use std::{
    io::{Cursor, Read, Seek},
    num::NonZero,
    ops::{BitAnd, BitOr},
};

use crate::{
    ReadIntLe,
    dir::Directory,
    file::FileId,
    header::{Command202, SyncHeader202Outgoing},
    message::MessageBody,
};

pub async fn query_directory<I: DirectoryInformation>(dir: &Directory, search_pattern: &str) -> Box<[I]> {
    let header = SyncHeader202Outgoing::from_tree_con(&dir.tree_connection, Command202::QueryDirectory);
    let output_buffer_length = dir.tree_connection.session().connection.max_transaction_size();
    let request = QueryDirectoryRequest {
        information_class: I::class(),
        flags: Flags::NONE,
        file_index: 0,
        file_id: dir.id,
        output_buffer_length,
        search_pattern,
    };
    let session = dir.tree_connection.session();
    let key = session.requires_signing().then_some(session.session_key()).copied();
    let (header, body) = session
        .connection
        .signup_message(header, &request, false, key)
        .await
        .unwrap();
    if let Some(code) = NonZero::new(header.status) {
        panic!("Server sent error code {code}");
    }
    QueryDirectoryResponse::read_from(&mut Cursor::new(body), output_buffer_length).0
}

#[derive(Clone, Copy, Debug)]
pub enum DirectoryInformationClass {
    Directory,
    FullDirectory,
    IdFullDirectory,
    BothDirectory,
    IdBothDirectory,
    Names,
    IdExtdDirectory,
    Id64ExtdDirectory,
    Id64ExtdBothDirectory,
    IdAllExtdDirectory,
    IdAllExtdBothDirectory,
    Reserved,
}
impl DirectoryInformationClass {
    pub fn to_int(self) -> u8 {
        match self {
            Self::Directory => 0x01,
            Self::FullDirectory => 0x02,
            Self::IdFullDirectory => 0x26,
            Self::BothDirectory => 0x03,
            Self::IdBothDirectory => 0x25,
            Self::Names => 0x0C,
            Self::IdExtdDirectory => 0x3C,
            Self::Id64ExtdDirectory => 0x4E,
            Self::Id64ExtdBothDirectory => 0x4F,
            Self::IdAllExtdDirectory => 0x50,
            Self::IdAllExtdBothDirectory => 0x51,
            Self::Reserved => 0x64,
        }
    }
}

#[derive(Debug)]
struct QueryDirectoryRequest<'sp> {
    pub information_class: DirectoryInformationClass,
    pub flags: Flags,
    pub file_index: u32,
    pub file_id: FileId,
    pub output_buffer_length: u32,
    pub search_pattern: &'sp str,
}
impl<'sp> QueryDirectoryRequest<'sp> {
    const STRUCTURE_SIZE: u16 = 33;
}
impl<'sp> MessageBody for QueryDirectoryRequest<'sp> {
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&Self::STRUCTURE_SIZE.to_le_bytes());
        w.push(self.information_class.to_int());
        w.push(self.flags.0);
        w.extend_from_slice(&self.file_index.to_le_bytes());
        let FileId { persistent, volatile } = self.file_id;
        w.extend_from_slice(&persistent);
        w.extend_from_slice(&volatile);
        let pat = crate::to_wide(self.search_pattern);
        let offset: u16 = 64 + 32;
        let length: u16 = pat.len() as u16;
        w.extend_from_slice(&offset.to_le_bytes());
        w.extend_from_slice(&length.to_le_bytes());
        w.extend_from_slice(&self.output_buffer_length.to_le_bytes());
        w.extend_from_slice(&pat);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Flags(u8);
impl Flags {
    pub const NONE: Self = Self(0);
    pub const RESTART_SCANS: Self = Self(0x01);
    pub const RETURN_SINGLE_ENTRY: Self = Self(0x02);
    pub const INDEX_SPECIFIED: Self = Self(0x04);
    pub const REOPEN: Self = Self(0x10);
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }
}
impl BitOr for Flags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl BitAnd for Flags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

struct QueryDirectoryResponse<I>(Box<[I]>);
impl<I> QueryDirectoryResponse<I> {
    const STRUCTURE_SIZE: u16 = 9;
}
impl<I: DirectoryInformation> QueryDirectoryResponse<I> {
    fn read_from<R: Read + Seek>(r: &mut R, max_output_buffer_length: u32) -> Self {
        if r.read_u16_le().unwrap() != Self::STRUCTURE_SIZE {
            panic!("Bad structure size");
        }
        let output_buffer_offset = r.read_u16_le().unwrap();
        let output_buffer_length = r.read_u32_le().unwrap();
        if output_buffer_length > max_output_buffer_length {
            panic!("exceeded max output buffer length")
        }
        let mut skip = vec![0; output_buffer_offset as usize - 64 - 8];
        r.read_exact(&mut skip).unwrap();
        let mut r = r.take(max_output_buffer_length.into());
        let mut last = false;
        let mut results = Vec::new();
        while !last {
            let (element, is_last) = I::read_from_buffer(&mut r).unwrap();
            last |= is_last;
            results.push(element);
        }
        Self(results.into_boxed_slice())
    }
}

pub trait DirectoryInformation: Sized {
    fn class() -> DirectoryInformationClass;
    fn read_from_buffer<R: Read + Seek>(r: &mut R) -> Result<(Self, bool), std::io::Error>;
}

#[derive(Clone, Debug)]
pub struct FileDirectoryInformation {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name: Box<str>,
}
impl DirectoryInformation for FileDirectoryInformation {
    fn class() -> DirectoryInformationClass {
        DirectoryInformationClass::Directory
    }
    fn read_from_buffer<R: Read + Seek>(r: &mut R) -> Result<(Self, bool), std::io::Error> {
        let next_entry_offset = r.read_u32_le()?;
        let file_index = r.read_u32_le()?;
        let creation_time = r.read_u64_le()?;
        let last_access_time = r.read_u64_le()?;
        let last_write_time = r.read_u64_le()?;
        let change_time = r.read_u64_le()?;
        let end_of_file = r.read_u64_le()?;
        let allocation_size = r.read_u64_le()?;
        let file_attributes = r.read_u32_le()?;
        let file_name_length = r.read_u32_le()?;
        let mut name_bytes = vec![0; file_name_length as usize];
        r.read_exact(&mut name_bytes)?;
        let file_name: Box<str> = crate::from_wide(&name_bytes).into_boxed_str();
        let returned = Self {
            file_index,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            end_of_file,
            allocation_size,
            file_attributes,
            file_name,
        };
        if next_entry_offset == 0 {
            Ok((returned, true))
        } else {
            r.seek_relative((next_entry_offset - 64 - file_name_length).into())?;
            Ok((returned, false))
        }
    }
}
