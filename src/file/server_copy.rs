use std::{
    ops::{Range, RangeInclusive, RangeTo, RangeToInclusive},
    sync::Arc,
};

use crate::{
    file::File,
    header::{Command202, SyncHeader202Outgoing},
    ioctl::{Flags, IoCtlRequest, IoCtlRequestKind},
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

pub(crate) async fn server_copy<T: FileRange>(from: &File, to: &File, chunks: &[Chunk<T>]) {
    if !Arc::ptr_eq(&from.tree_connection, &to.tree_connection) {
        panic!("files from different tree connection");
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
