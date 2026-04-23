use std::io::{Read, Seek};

#[cfg(feature = "chrono")]
use chrono::{DateTime, Utc};

use crate::{
    ReadIntLe,
    dir::query::{DirectoryInformationClass, QueryInformation},
};

#[derive(Clone, Debug)]
pub struct DirectoryInformation {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_name: Box<str>,
}
impl DirectoryInformation {
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
impl QueryInformation for DirectoryInformation {
    fn class() -> DirectoryInformationClass {
        DirectoryInformationClass::Directory
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
        let file_attributes = r.read_u32_le()?;
        let file_name_length = r.read_u32_le()?;
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
