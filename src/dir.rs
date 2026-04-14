use std::{num::NonZero, sync::Arc};

use crate::{
    file::{
        AccessMask, CreateDisposition, CreateResponse, FileCreateRequest, ImpersonationLevel,
        ShareAccess,
    },
    header::{Command202, SyncHeader202Outgoing},
    tree::TreeConnection,
};

pub(crate) async fn create_dir(
    tree_connection: Arc<TreeConnection>,
    path: &str,
    create_disposition: DirCreateDisposition,
) {
    let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Create);
    let request = FileCreateRequest {
        oplock_level: None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access: AccessMask::READ_DATA,
        file_attributes: 0x0,
        share_access: ShareAccess::SHARE_READ,
        create_disposition: create_disposition.into(),
        create_options: 0x1 | 0x200,
        path,
    };
    let session = tree_connection.session();
    let key = session
        .requires_signing()
        .then_some(session.session_key())
        .copied();
    let (header, body) = session
        .connection
        .signup_message(header, &request, false, key)
        .await
        .unwrap();
    if let Some(code) = NonZero::new(header.status) {
        panic!("Server sent code {code}");
    }
    let CreateResponse {
        oplock_level,
        create_action,
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        allocation_size,
        end_of_file,
        attributes,
        id,
    } = CreateResponse::read_from(&mut body.as_ref()).unwrap();
}

#[derive(Clone, Copy, Debug, Default)]
/// Directories can only be opened with these three options
pub enum DirCreateDisposition {
    #[default]
    Open,
    Create,
    OpenIf,
}

impl From<DirCreateDisposition> for CreateDisposition {
    fn from(value: DirCreateDisposition) -> Self {
        match value {
            DirCreateDisposition::Open => Self::Open,
            DirCreateDisposition::Create => Self::Create,
            DirCreateDisposition::OpenIf => Self::OpenIf,
        }
    }
}
