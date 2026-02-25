#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    persistent: u64,
    volatile: u64,
}
impl FileId {
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self { persistent, volatile }
    }
}

pub struct File {
    pub(crate) file_id: FileId,
}
