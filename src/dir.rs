use std::{num::NonZero, sync::Arc};

use crate::{
    error::{ErrorResponse2, ServerError},
    file::{
        AccessMask, CreateDisposition, CreateResponse, FileCreateRequest, ImpersonationLevel,
        ShareAccess,
    },
    header::{Command202, SyncHeader202Outgoing},
    message,
    tree::TreeConnection,
};

pub(crate) async fn create_dir(
    tree_connection: Arc<TreeConnection>,
    path: &str,
    create_disposition: DirCreateDisposition,
) -> Result<(), CreateDirError> {
    let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Create);
    let request = FileCreateRequest {
        oplock_level: None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access: AccessMask::READ_DATA,
        file_attributes: 0x0,
        share_access: ShareAccess::SHARE_READ,
        create_disposition: create_disposition.into(),
        create_options: 0x1,
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
        .map_err(|err| match err {
            message::WriteError::Connection(error) => CreateDirError::Io(error),
            message::WriteError::MessageTooLong => CreateDirError::InvalidMessage,
        })?;
    if let Some(code) = NonZero::new(header.status) {
        return Err(ServerError::handle_error_body(code, &body));
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
    Ok(())
}

#[derive(Debug)]
pub enum CreateDirError {
    InvalidMessage,
    Io(std::io::Error),
    ServerError {
        code: NonZero<u32>,
        body: ErrorResponse2,
    },
}
impl From<std::io::Error> for CreateDirError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl ServerError for CreateDirError {
    fn invalid_message() -> Self {
        Self::InvalidMessage
    }

    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self {
        Self::ServerError { code, body }
    }
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
