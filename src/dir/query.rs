use std::{
    fmt::Display,
    io::{Cursor, Read, Seek},
    num::NonZero,
    ops::{BitAnd, BitOr},
};

use crate::{
    ReadIntLe,
    dir::Directory,
    error::{ErrorResponse2, ServerError},
    file::FileId,
    header::{Command, SyncHeaderOutgoing},
    message::{MessageBody, WriteError},
    tree::Tree,
};

mod both_directory_information;
mod directory_information;
mod full_directory_information;
mod id_full_directory_information;
mod names_information;

pub use both_directory_information::BothDirectoryInformation;
pub use directory_information::DirectoryInformation;
pub use full_directory_information::FullDirectoryInformation;
pub use id_full_directory_information::IdFullDirectoryInformation;
pub use names_information::NamesInformation;

pub async fn query_directory<I: QueryInformation>(
    dir: &Directory,
    search_pattern: &str,
    max_output_length: Option<u32>,
) -> Result<Box<[I]>, QueryDirectoryError> {
    let header = SyncHeaderOutgoing::from_tree_con(dir.tree_connection.as_ref(), Command::QueryDirectory);
    let output_buffer_length =
        max_output_length.unwrap_or(dir.tree_connection.session().connection.max_transaction_size());
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
        .map_err(|we| match we {
            WriteError::Connection(error) => QueryDirectoryError::Io(error),
            WriteError::NotEnoughCredits => QueryDirectoryError::NotEnoughCredits,
            WriteError::MessageTooLong => QueryDirectoryError::InvalidMessage,
        })?;
    if let Some(code) = NonZero::new(header.status) {
        return Err(QueryDirectoryError::handle_error_body(code, &body));
    }
    match QueryDirectoryResponse::read_from(&mut Cursor::new(body), output_buffer_length) {
        Ok(q) => Ok(q.0),
        Err(err) => Err(QueryDirectoryError::Io(err)),
    }
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
    fn send_payload_size(&self) -> u32 {
        crate::to_wide(self.search_pattern).len() as u32
    }
    fn expected_response_payload_size(&self) -> u32 {
        self.output_buffer_length
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
impl<I: QueryInformation> QueryDirectoryResponse<I> {
    fn read_from<R: Read + Seek>(r: &mut R, max_output_buffer_length: u32) -> Result<Self, std::io::Error> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            panic!("Bad structure size");
        }
        let output_buffer_offset = r.read_u16_le()?;
        let output_buffer_length = r.read_u32_le()?;
        if output_buffer_length > max_output_buffer_length {
            panic!("exceeded max output buffer length")
        }
        let mut skip = vec![0; output_buffer_offset as usize - 64 - 8];
        r.read_exact(&mut skip)?;
        let mut r = r.take(max_output_buffer_length.into());
        let mut last = false;
        let mut results = Vec::new();
        while !last {
            let (element, is_last) = I::read_from_buffer(&mut r)?;
            last |= is_last;
            results.push(element);
        }
        Ok(Self(results.into_boxed_slice()))
    }
}

pub trait QueryInformation: Sized {
    fn class() -> DirectoryInformationClass;
    fn read_from_buffer<R: Read + Seek>(r: &mut R) -> Result<(Self, bool), std::io::Error>;
}

#[derive(Debug)]
pub enum QueryDirectoryError {
    InvalidMessage,
    NotEnoughCredits,
    Io(std::io::Error),
    ServerError { code: NonZero<u32>, body: ErrorResponse2 },
}
impl std::error::Error for QueryDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMessage | Self::NotEnoughCredits | Self::ServerError { .. } => None,
            Self::Io(error) => Some(error),
        }
    }
}
impl ServerError for QueryDirectoryError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }

    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
}
impl From<std::io::Error> for QueryDirectoryError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl Display for QueryDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage => write!(f, "Invalid message"),
            Self::NotEnoughCredits => write!(f, "Not enough credits"),
            Self::ServerError { code, .. } => write!(f, "Server sent an error code: {code}"),
            Self::Io(error) => write!(f, "IO error: {error}"),
        }
    }
}
