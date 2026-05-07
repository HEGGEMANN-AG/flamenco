use std::io::Read;

#[cfg(feature = "chrono")]
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta, Utc};

pub mod attributes;
pub mod client;
pub mod connection;
mod credits;
pub mod dir;
mod error;
pub mod file;
mod header;
mod ioctl;
mod message;
mod negotiate;
mod netbios;
pub mod session;
mod share_name;
mod sign;
pub mod tree;

pub const SMB_DEFAULT_PORT: u16 = 445;

fn from_wide(arr: &[u8]) -> String {
    assert!(arr.len().is_multiple_of(2));
    arr.as_chunks::<2>()
        .0
        .iter()
        .map(|twobytes| char::from_u32(u16::from_le_bytes(*twobytes).into()).unwrap())
        .collect()
}

fn to_wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>()
}

pub(crate) trait ReadIntLe: Read {
    fn read_u16_le(&mut self) -> std::io::Result<u16> {
        let mut arr = [0u8; 2];
        self.read_exact(&mut arr)?;
        Ok(u16::from_le_bytes(arr))
    }
    fn read_u32_le(&mut self) -> std::io::Result<u32> {
        let mut arr = [0u8; 4];
        self.read_exact(&mut arr)?;
        Ok(u32::from_le_bytes(arr))
    }
    fn read_u64_le(&mut self) -> std::io::Result<u64> {
        let mut arr = [0u8; 8];
        self.read_exact(&mut arr)?;
        Ok(u64::from_le_bytes(arr))
    }
}
impl<R: Read> ReadIntLe for R {}

#[cfg(feature = "chrono")]
const JANUARY_FIRST_1601: NaiveDate = NaiveDate::from_ymd_opt(1601, 1, 1).unwrap();

#[cfg(feature = "chrono")]
fn chrono_from_filetime(u: u64) -> DateTime<Utc> {
    NaiveDateTime::new(JANUARY_FIRST_1601, NaiveTime::default())
        .and_utc()
        .checked_add_signed(TimeDelta::nanoseconds((u * 100).try_into().unwrap()))
        .unwrap()
}
