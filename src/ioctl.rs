use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io::{Read, Seek},
    ops::RangeInclusive,
};

use crate::{
    ReadIntLe,
    file::{
        FileId,
        server_copy::{Chunk, FileRange},
    },
    message::MessageBody,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlCode {
    DfsGetReferrals,
    PipePeek,
    PipeWait,
    PipeTransceive,
    SrvCopyChunk,
    SrvEnumerateSnapshots,
    SrvRequestResumeKey,
    SrvReadHash,
    SrvCopyChunkWrite,
    LmrRequestResiliency,
    QueryNetworkInterfaceInfo,
    SetReparsePoint,
    DfsGetReferralsEx,
    FileLevelTrim,
    ValidateNegotiateInfo,
}
impl ControlCode {
    pub const fn to_int(self) -> u32 {
        match self {
            Self::DfsGetReferrals => 0x00060194,
            Self::PipePeek => 0x0011400C,
            Self::PipeWait => 0x00110018,
            Self::PipeTransceive => 0x0011C017,
            Self::SrvCopyChunk => 0x001440F2,
            Self::SrvEnumerateSnapshots => 0x00144064,
            Self::SrvRequestResumeKey => 0x00140078,
            Self::SrvReadHash => 0x001441bb,
            Self::SrvCopyChunkWrite => 0x001480F2,
            Self::LmrRequestResiliency => 0x001401D4,
            Self::QueryNetworkInterfaceInfo => 0x001401FC,
            Self::SetReparsePoint => 0x000900A4,
            Self::DfsGetReferralsEx => 0x000601B0,
            Self::FileLevelTrim => 0x00098208,
            Self::ValidateNegotiateInfo => 0x00140204,
        }
    }
    pub const fn from_int(i: u32) -> Option<Self> {
        match i {
            0x00060194 => Some(Self::DfsGetReferrals),
            0x0011400C => Some(Self::PipePeek),
            0x00110018 => Some(Self::PipeWait),
            0x0011C017 => Some(Self::PipeTransceive),
            0x001440F2 => Some(Self::SrvCopyChunk),
            0x00144064 => Some(Self::SrvEnumerateSnapshots),
            0x00140078 => Some(Self::SrvRequestResumeKey),
            0x001441bb => Some(Self::SrvReadHash),
            0x001480F2 => Some(Self::SrvCopyChunkWrite),
            0x001401D4 => Some(Self::LmrRequestResiliency),
            0x001401FC => Some(Self::QueryNetworkInterfaceInfo),
            0x000900A4 => Some(Self::SetReparsePoint),
            0x000601B0 => Some(Self::DfsGetReferralsEx),
            0x00098208 => Some(Self::FileLevelTrim),
            0x00140204 => Some(Self::ValidateNegotiateInfo),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Flags {
    IoCtl,
    FsCtl,
}
impl Flags {
    pub const fn to_int(self) -> u32 {
        match self {
            Self::IoCtl => 0x00,
            Self::FsCtl => 0x01,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum IoCtlRequestKind<'c, T = RangeInclusive<u64>> {
    SrvCopyChunk {
        source_key: &'c SourceKey,
        chunks: &'c [Chunk<T>],
    },
    SrvRequestResumeKey,
}
impl<T> IoCtlRequestKind<'_, T> {
    pub fn code(&self) -> ControlCode {
        match self {
            Self::SrvCopyChunk { .. } => ControlCode::SrvCopyChunk,
            Self::SrvRequestResumeKey => ControlCode::SrvRequestResumeKey,
        }
    }
    fn input_buffer_length(&self) -> u32 {
        match self {
            Self::SrvRequestResumeKey => 0,
            Self::SrvCopyChunk { chunks, .. } => 32 + chunks.len() as u32 * 24,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IoCtlRequest<'c, T = RangeInclusive<u64>> {
    pub(crate) kind: IoCtlRequestKind<'c, T>,
    pub(crate) file_id: FileId,
    pub(crate) max_input_response: u32,
    pub(crate) max_output_reponse: u32,
    pub(crate) flags: Flags,
}

impl<'c, T> IoCtlRequest<'c, T> {
    const STRUCTURE_SIZE: u16 = 57;
}
impl<'c, T: FileRange> MessageBody for IoCtlRequest<'c, T> {
    fn size_hint(&self) -> usize {
        56
    }
    fn write_to(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&Self::STRUCTURE_SIZE.to_le_bytes());
        w.extend(0u16.to_le_bytes());
        w.extend_from_slice(&self.kind.code().to_int().to_le_bytes());
        w.extend_from_slice(&self.file_id.persistent);
        w.extend_from_slice(&self.file_id.volatile);
        // input offset
        let input_offset: u32 = if self.kind.input_buffer_length() == 0 {
            0
        } else {
            64 + 56
        };
        w.extend_from_slice(&input_offset.to_le_bytes());
        // input count
        w.extend_from_slice(&self.kind.input_buffer_length().to_le_bytes());

        w.extend_from_slice(&self.max_input_response.to_le_bytes());
        // output offset
        w.extend_from_slice(&0u32.to_le_bytes());
        // output count
        w.extend_from_slice(&0u32.to_le_bytes());

        w.extend_from_slice(&self.max_output_reponse.to_le_bytes());

        w.extend_from_slice(&self.flags.to_int().to_le_bytes());

        // reserved2
        w.extend_from_slice(&0u32.to_le_bytes());
        match self.kind {
            IoCtlRequestKind::SrvCopyChunk { source_key, chunks } => {
                w.extend_from_slice(source_key.as_arr());
                let chunk_count: u32 = chunks.len().try_into().expect("too many chunks");
                w.extend_from_slice(&chunk_count.to_le_bytes());
                // Reserved
                w.extend_from_slice(&0u32.to_le_bytes());
                for chunk in chunks {
                    w.extend_from_slice(&chunk.source_range.start().to_le_bytes());
                    w.extend_from_slice(&chunk.target_start.to_le_bytes());
                    w.extend_from_slice(&(chunk.source_range.length() as u32).to_le_bytes());
                    w.extend_from_slice(&0u32.to_le_bytes());
                }
            }
            IoCtlRequestKind::SrvRequestResumeKey => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceKey([u8; 24]);
impl SourceKey {
    pub fn new(arr: [u8; 24]) -> Self {
        Self(arr)
    }
    pub fn as_arr(&self) -> &[u8; 24] {
        &self.0
    }
}

pub(crate) struct IoCtlResponse {
    pub code: ControlCode,
    pub file_id: FileId,
    pub flags: u32,
    pub buffer: Box<[u8]>,
}

impl IoCtlResponse {
    const STRUCTURE_SIZE: u16 = 49;
    pub fn read_from<R: Read + Seek>(mut r: R) -> Result<Self, ReadError> {
        if r.read_u16_le()? != Self::STRUCTURE_SIZE {
            return Err(ReadError::InvalidStructureSize);
        }
        let _reserved = r.read_u16_le()?;
        let craw = r.read_u32_le()?;
        let Some(code) = ControlCode::from_int(craw) else {
            return Err(ReadError::InvalidControlCode);
        };
        let mut file_id = [0u8; 16];
        r.read_exact(&mut file_id)?;
        let file_id = FileId::from(file_id);
        let input_offset = r.read_u32_le()?;
        let input_count = r.read_u32_le()?;
        assert_eq!(input_count, 0);
        let output_offset = r.read_u32_le()?;
        assert_eq!(input_offset, output_offset);
        let output_count = r.read_u32_le()?;
        let flags = r.read_u32_le()?;
        let _reserved2 = r.read_u32_le()?;
        let offset_from_end_of_buffer = (output_offset - 64 - 48) as usize;
        r.seek_relative(offset_from_end_of_buffer as i64)?;
        let buffer = if output_count == 0 {
            Box::default()
        } else {
            let mut output = vec![0; output_count as usize];
            r.read_exact(&mut output)?;
            output.into_boxed_slice()
        };
        Ok(Self {
            code,
            file_id,
            flags,
            buffer,
        })
    }
}

#[derive(Debug)]
pub enum ReadError {
    InvalidStructureSize,
    InvalidControlCode,
    Io(std::io::Error),
}
impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::InvalidStructureSize => write!(f, "Invalid structure size field"),
            Self::Io(io) => write!(f, "Error reading: {io}"),
            Self::InvalidControlCode => write!(f, "Invalid control code"),
        }
    }
}
impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
