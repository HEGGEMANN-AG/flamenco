use std::{
    io::{Read, Seek},
    num::NonZero,
};

#[cfg(feature = "chrono")]
use chrono::{DateTime, Utc};

use crate::{
    ReadIntLe,
    attributes::FileAttributes,
    dir::query::{DirectoryInformationClass, QueryInformation},
    file::ShortFileId,
};

#[derive(Clone, Debug)]
pub struct IdFullDirectoryInformation {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    pub ea_size: u32,
    pub file_id: Option<ShortFileId>,
    pub file_name: Box<str>,
}
impl IdFullDirectoryInformation {
    #[cfg(feature = "chrono")]
    pub fn creation_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.creation_time)
    }
    #[cfg(feature = "chrono")]
    pub fn last_access_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.last_access_time)
    }
    #[cfg(feature = "chrono")]
    pub fn last_write_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.last_write_time)
    }
    #[cfg(feature = "chrono")]
    pub fn change_time(&self) -> DateTime<Utc> {
        crate::chrono_from_filetime(self.change_time)
    }
}
impl QueryInformation for IdFullDirectoryInformation {
    fn class() -> DirectoryInformationClass {
        DirectoryInformationClass::IdFullDirectory
    }
    fn read_from_buffer<R: Read + Seek>(r: &mut R) -> Result<(Self, bool), std::io::Error> {
        let next_entry_offset = r.read_u32_le()?;
        let file_index = r.read_u32_le()?;
        let creation_time = r.read_u64_le()?;
        let last_access_time = r.read_u64_le()?;
        let last_write_time = r.read_u64_le()?;
        let change_time = r.read_u64_le()?;
        let end_of_file = r.read_u64_le()?;
        let allocation_size = r.read_u64_le()?;
        let file_attributes = FileAttributes::from_int(r.read_u32_le()?);
        let file_name_length = r.read_u32_le()?;
        let ea_size = r.read_u32_le()?;
        let _reserved = r.read_u32_le()?;
        let file_id = NonZero::new(r.read_u64_le()?).map(ShortFileId);
        let mut name_bytes = vec![0; file_name_length as usize];
        r.read_exact(&mut name_bytes)?;
        let file_name: Box<str> = crate::from_wide(&name_bytes).into_boxed_str();
        let returned = Self {
            file_index,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            end_of_file,
            allocation_size,
            ea_size,
            file_id,
            file_attributes,
            file_name,
        };
        if next_entry_offset == 0 {
            Ok((returned, true))
        } else {
            r.seek_relative((next_entry_offset - 64 - file_name_length).into())?;
            Ok((returned, false))
        }
    }
}
