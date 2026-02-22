#[derive(Debug)]
pub struct FileId {
    persistent: u64,
    volatile: u64,
}
impl FileId {
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self { persistent, volatile }
    }
}
