use crate::{
    header::{Command202, SyncHeader202Outgoing},
    tree::TreeConnection,
};

#[derive(Debug)]
pub struct FileHandle<'client, 'con, 'cred, 'session, 'tree> {
    tree_connection: &'tree mut TreeConnection<'client, 'con, 'cred, 'session>,
}
impl FileHandle<'_, '_, '_, '_, '_> {
    pub(crate) fn new<'tree, 'client, 'con, 'cred, 'session>(
        tree_connect: &'tree mut TreeConnection<'client, 'con, 'cred, 'session>,
    ) -> FileHandle<'client, 'con, 'cred, 'session, 'tree> {
        let header = SyncHeader202Outgoing::from_tree_con(tree_connect, Command202::Create);
        todo!()
    }
}
