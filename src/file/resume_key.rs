use std::{io::Cursor, num::NonZero, ops::RangeInclusive};

use crate::{
    file::File,
    header::{Command202, SyncHeader202Outgoing},
    ioctl::{ControlCode, Flags, IoCtlRequest, IoCtlRequestKind, IoCtlResponse, SourceKey},
};

pub(crate) async fn get_resume_key(file: &File) -> SourceKey {
    let header = SyncHeader202Outgoing::from_tree_con(&file.tree_connection, Command202::IoCtl);
    let request = IoCtlRequest {
        kind: IoCtlRequestKind::<RangeInclusive<u64>>::SrvRequestResumeKey,
        file_id: file.id,
        max_input_response: 0,
        max_output_reponse: 32,
        flags: Flags::FsCtl,
    };
    let session = file.tree_connection.session();
    let key = session.requires_signing().then_some(session.session_key()).copied();
    let (header, body) = session
        .connection
        .signup_message(header, &request, false, key)
        .await
        .unwrap();
    if let Some(status) = NonZero::new(header.status) {
        panic!("Server returned error code: {status}");
    }
    let response = IoCtlResponse::read_from(Cursor::new(body));
    assert_eq!(response.code, ControlCode::SrvRequestResumeKey);
    let arr: &[u8; 24] = response.buffer.first_chunk().unwrap();
    SourceKey::new(*arr)
}
