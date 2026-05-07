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
    header::{Command, SyncHeaderOutgoing},
    ioctl::{Flags, IoCtlRequest, IoCtlRequestKind, IoCtlResponse, ReadError},
    message::WriteError,
    tree::Tree,
};

const INVALID_PARAMETER: u32 = 0xc000000d;

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
    let out_header = SyncHeaderOutgoing::from_tree_con(tc.as_ref(), Command::IoCtl);
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
        .map_err(|we| match we {
            WriteError::NotEnoughCredits => ServerCopyError::NotEnoughCredits,
            WriteError::Connection(error) => ServerCopyError::Io(error),
            WriteError::MessageTooLong => ServerCopyError::InvalidMessage,
        })?;
    let is_invalid_param = header.status == INVALID_PARAMETER;
    if let Some(code) = NonZero::new(header.status)
        && !is_invalid_param
    {
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
    if is_invalid_param {
        Err(ServerCopyError::Refused {
            max_chunk_count: chunks_written,
            max_chunk_size: chunk_bytes_written,
            max_total_copy: total_bytes_written,
        })
    } else {
        Ok(ServerCopyResponse {
            chunks_written,
            chunk_bytes_written,
            total_bytes_written,
        })
    }
}

#[derive(Debug)]
pub enum ServerCopyError {
    FilesFromDifferentTrees,
    NotEnoughCredits,
    Io(std::io::Error),
    InvalidMessage,
    Refused {
        max_chunk_count: u32,
        max_chunk_size: u32,
        max_total_copy: u32,
    },
    ServerError(NonZero<u32>, ErrorResponse2),
}
impl std::error::Error for ServerCopyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(io) => Some(io),
            Self::Refused { .. }
            | Self::FilesFromDifferentTrees
            | Self::NotEnoughCredits
            | Self::InvalidMessage
            | Self::ServerError(_, _) => None,
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
            Self::NotEnoughCredits => write!(f, "Not enough credits for this operation"),
            Self::Io(io) => write!(f, "An error occured while reading or writing: {io}"),
            Self::Refused {
                max_chunk_count,
                max_chunk_size,
                max_total_copy,
            } => write!(
                f,
                "Server refused to copy. It only accepts ({max_chunk_count} chunks at maximum {max_chunk_size} size for a maximum total of {max_total_copy}"
            ),
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
