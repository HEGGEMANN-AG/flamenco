use std::{
    fmt::Display,
    io::Cursor,
    num::NonZero,
    ops::{Range, RangeInclusive, RangeTo, RangeToInclusive},
    sync::Arc,
};

use crate::{
    ReadIntLe,
    error::{ErrorResponse2, ServerError},
    file::File,
    header::{Command202, SyncHeader202Outgoing},
    ioctl::{Flags, IoCtlRequest, IoCtlRequestKind, IoCtlResponse, ReadError},
};

#[derive(Debug, Clone, Copy)]
pub struct Chunk<Range = RangeInclusive<u64>> {
    pub(crate) source_range: Range,
    pub(crate) target_start: u64,
}
impl Chunk<RangeInclusive<u64>> {
    pub fn new<R: FileRange>(range: R, target_start: u64) -> Option<Chunk<R>> {
        u32::try_from(range.length()).is_ok().then_some(Chunk {
            source_range: range,
            target_start,
        })
    }
}

pub(crate) async fn server_copy<T: FileRange>(
    from: &File,
    to: &File,
    chunks: &[Chunk<T>],
) -> Result<ServerCopyResponse, ServerCopyError> {
    if !Arc::ptr_eq(&from.tree_connection, &to.tree_connection) {
        return Err(ServerCopyError::FilesFromDifferentTrees);
    }
    let tc = &from.tree_connection;
    let source_key = from.get_resume_key().await;
    let out_header = SyncHeader202Outgoing::from_tree_con(tc, Command202::IoCtl);
    let session_key = tc
        .session()
        .requires_signing()
        .then_some(tc.session().session_key())
        .copied();
    let kind = IoCtlRequestKind::SrvCopyChunk {
        source_key: &source_key,
        chunks,
    };
    let ioctl = IoCtlRequest {
        kind,
        file_id: to.id,
        max_input_response: 0,
        max_output_reponse: 12,
        flags: Flags::FsCtl,
    };
    let (header, body) = tc
        .session()
        .connection
        .signup_message(out_header, &ioctl, false, session_key)
        .await
        .unwrap();
    if let Some(code) = NonZero::new(header.status) {
        return Err(ServerCopyError::handle_error_body(code, &body));
    }
    let ioctl = IoCtlResponse::read_from(Cursor::new(body)).map_err(|re| match re {
        ReadError::InvalidStructureSize | ReadError::InvalidControlCode => ServerCopyError::InvalidMessage,
        ReadError::Io(error) => ServerCopyError::Io(error),
    })?;
    let mut server_copy_resp: &[u8] = &ioctl.buffer;
    let chunks_written = server_copy_resp.read_u32_le()?;
    let chunk_bytes_written = server_copy_resp.read_u32_le()?;
    let total_bytes_written = server_copy_resp.read_u32_le()?;
    Ok(ServerCopyResponse {
        chunks_written,
        chunk_bytes_written,
        total_bytes_written,
    })
}

#[derive(Debug)]
pub enum ServerCopyError {
    FilesFromDifferentTrees,
    Io(std::io::Error),
    InvalidMessage,
    ServerError(NonZero<u32>, ErrorResponse2),
}
impl std::error::Error for ServerCopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::FilesFromDifferentTrees | Self::InvalidMessage | Self::ServerError(_, _) => None,
        }
    }
}
impl From<std::io::Error> for ServerCopyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl Display for ServerCopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FilesFromDifferentTrees => write!(f, "The file handles provided are from different tree connections"),
            Self::InvalidMessage => write!(f, "A message sent by the server was invalid"),
            Self::Io(io) => write!(f, "An error occured while reading or writing: {io}"),
            Self::ServerError(code, _) => write!(f, "the server sent an error code {code}"),
        }
    }
}
impl ServerError for ServerCopyError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }

    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError(code, body)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServerCopyResponse {
    pub chunks_written: u32,
    /// Number of bytes successfully written in the last failed write
    pub chunk_bytes_written: u32,
    /// Total number of bytes successfully written
    pub total_bytes_written: u32,
}

pub trait FileRange {
    fn start(&self) -> u64;
    fn length(&self) -> u64;
}
impl FileRange for RangeToInclusive<u64> {
    fn start(&self) -> u64 {
        0
    }
    fn length(&self) -> u64 {
        self.end + 1
    }
}
impl FileRange for RangeInclusive<u64> {
    fn start(&self) -> u64 {
        *self.start()
    }
    fn length(&self) -> u64 {
        self.end() - self.start() + 1
    }
}
impl FileRange for Range<u64> {
    fn start(&self) -> u64 {
        self.start
    }
    fn length(&self) -> u64 {
        self.end - self.start
    }
}
impl FileRange for RangeTo<u64> {
    fn start(&self) -> u64 {
        0
    }
    fn length(&self) -> u64 {
        self.end
    }
}
