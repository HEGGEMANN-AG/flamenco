use std::{num::NonZero, sync::Arc};

use crate::{
    attributes::FileAttributes,
    error::{ErrorResponse2, ServerError},
    file::{
        self, AccessMask, FileId, ImpersonationLevel, OplockLevel202, ShareAccess,
        close::{CloseRequest, CloseResponse},
        create::{CreateDisposition, CreateResponse, FileCreateRequest},
        verify_close_header,
    },
    header::{Command202, SyncHeader202Outgoing},
    message::{self, WriteError},
    tree::TreeConnection,
};

pub mod query;

pub struct Directory {
    tree_connection: Arc<TreeConnection>,
    id: FileId,
    oplock_level: Option<OplockLevel202>,
    allocation_size: u64,
    end_of_file: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
}

pub(crate) async fn open(
    tree_connection: &Arc<TreeConnection>,
    path: &str,
    create_disposition: DirCreateDisposition,
) -> Result<Directory, CreateDirError> {
    let header = SyncHeader202Outgoing::from_tree_con(tree_connection, Command202::Create);
    let request = FileCreateRequest {
        oplock_level: None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access: AccessMask::READ_DATA | AccessMask::READ_ATTRIBUTES,
        file_attributes: FileAttributes::EMPTY,
        share_access: ShareAccess::SHARE_READ,
        create_disposition: create_disposition.into(),
        create_options: 0x1,
        path,
    };
    let session = tree_connection.session();
    let key = session.requires_signing().then_some(session.session_key()).copied();
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
    } = CreateResponse::read_from(&mut body.as_ref()).map_err(|err| match err {
        file::create::ReadError::Io(error) => CreateDirError::Io(error),
        file::create::ReadError::InvalidStructureSize
        | file::create::ReadError::InvalidOplockLevel
        | file::create::ReadError::InvalidCreateAction => CreateDirError::InvalidMessage,
    })?;
    if !attributes.contains(FileAttributes::DIRECTORY) {
        return Err(CreateDirError::NotADirectory);
    }
    Ok(Directory {
        tree_connection: tree_connection.clone(),
        id,
        oplock_level,
        allocation_size,
        end_of_file,
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
    })
}
impl Directory {
    async fn send_close(&mut self) -> Result<(), std::io::Error> {
        Self::send_close_raw(self.tree_connection.clone(), self.id).await
    }
    async fn send_close_raw(tree_connection: Arc<TreeConnection>, id: FileId) -> Result<(), std::io::Error> {
        let header = SyncHeader202Outgoing::from_tree_con(&tree_connection, Command202::Close);
        let session = tree_connection.session();
        let session_key = session.requires_signing().then_some(session.session_key()).copied();
        let (header, body) = match session
            .connection
            .signup_message(header, &CloseRequest { id }, false, session_key)
            .await
        {
            Ok(t) => t,
            Err(WriteError::Connection(io)) => return Err(io),
            Err(WriteError::MessageTooLong) => unreachable!(),
        };
        if let Some(code) = NonZero::new(header.status) {
            panic!("Error with code {code}");
        }
        let _ = verify_close_header(&header);
        let _body = CloseResponse::read_from(&mut body.as_ref());
        Ok(())
    }
    pub async fn close(mut self) -> Result<(), std::io::Error> {
        self.send_close().await
    }
    pub async fn query<I: query::DirectoryInformation>(&self, search_pattern: &str) -> Box<[I]> {
        query::query_directory(self, search_pattern).await
    }
}

#[derive(Debug)]
pub enum CreateDirError {
    InvalidMessage,
    NotADirectory,
    Io(std::io::Error),
    ServerError { code: NonZero<u32>, body: ErrorResponse2 },
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
    /// If the file already exists, return success; otherwise, fail the operation.
    Open,
    /// If the file already exists, fail the operation; otherwise, create the file.
    Create,
    /// Open the file if it already exists; otherwise, create the file.
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
