use std::{cmp::Ordering, io::ErrorKind, num::NonZero};

#[derive(Debug)]
pub struct ErrorResponse2(Box<[u8]>);
impl ErrorResponse2 {
    fn from_bytes(b: &[u8]) -> Result<Self, ParseError> {
        let Some((structure_body, error_data)) = b
            .split_first_chunk::<8>()
            .map(|(a, err)| (a.as_array::<8>().unwrap(), err))
        else {
            return Err(ParseError::UnexpectedEof);
        };
        if u16::from_le_bytes(*structure_body.first_chunk().unwrap()) != 9 {
            return Err(ParseError::InvalidStructureSize);
        }
        if structure_body[2] != 0 {
            return Err(ParseError::ContextNotSupported);
        }
        // ignore reserved
        let byte_count = u32::from_le_bytes(*structure_body.last_chunk().unwrap());
        match (byte_count as usize).cmp(&error_data.len()) {
            Ordering::Less => Err(ParseError::ExcessTrailingBytes),
            Ordering::Equal => Ok(ErrorResponse2(error_data.into())),
            Ordering::Greater => Err(ParseError::UnexpectedEof),
        }
    }
}

#[derive(Debug)]
enum ParseError {
    InvalidStructureSize,
    UnexpectedEof,
    ExcessTrailingBytes,
    ContextNotSupported,
}

pub trait ServerError: Sized + From<std::io::Error> {
    fn invalid_message() -> Self;
    fn parsed(code: NonZero<u32>, body: ErrorResponse2) -> Self;
    fn handle_error_body(code: NonZero<u32>, b: &[u8]) -> Self {
        match ErrorResponse2::from_bytes(b) {
            Ok(body) => Self::parsed(code, body),
            Err(
                ParseError::ContextNotSupported
                | ParseError::ExcessTrailingBytes
                | ParseError::InvalidStructureSize,
            ) => Self::invalid_message(),
            Err(ParseError::UnexpectedEof) => Self::from(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "error body ended early",
            )),
        }
    }
}
