use std::io::{Read, Seek};

use crate::{
    ReadIntLe,
    dir::query::{DirectoryInformationClass, QueryInformation},
};

#[derive(Clone, Debug)]
pub struct NamesInformation {
    pub file_index: u32,
    pub file_name: Box<str>,
}
impl QueryInformation for NamesInformation {
    fn class() -> DirectoryInformationClass {
        DirectoryInformationClass::Names
    }
    fn read_from_buffer<R: Read + Seek>(r: &mut R) -> Result<(Self, bool), std::io::Error> {
        let next_entry_offset = r.read_u32_le()?;
        let file_index = r.read_u32_le()?;
        let file_name_length = r.read_u32_le()?;
        let mut name_bytes = vec![0; file_name_length as usize];
        r.read_exact(&mut name_bytes)?;
        let file_name: Box<str> = crate::from_wide(&name_bytes).into_boxed_str();
        let returned = Self { file_index, file_name };
        if next_entry_offset == 0 {
            Ok((returned, true))
        } else {
            r.seek_relative((next_entry_offset - 64 - file_name_length).into())?;
            Ok((returned, false))
        }
    }
}
