use std::cmp::Ordering;

#[derive(Debug)]
pub struct ErrorResponse2(Box<[u8]>);
impl ErrorResponse2 {
    pub fn from_bytes(b: &[u8]) -> Result<Self, ParseError> {
        let Some((structure_body, error_data)) = b
            .split_at_checked(8)
            .map(|(a, err)| (a.as_array::<8>().unwrap(), err))
        else {
            return Err(ParseError::UnexpectedEof);
        };
        if u16::from_le_bytes(*structure_body[0..2].as_array().unwrap()) != 9 {
            return Err(ParseError::InvalidStructureSize);
        }
        if structure_body[2] != 0 {
            return Err(ParseError::ContextNotSupported);
        }
        // ignore reserved
        let byte_count = u32::from_le_bytes(*structure_body[4..8].as_array().unwrap());
        match (byte_count as usize).cmp(&error_data.len()) {
            Ordering::Less => Err(ParseError::ExcessTrailingBytes),
            Ordering::Equal => Ok(ErrorResponse2(error_data.into())),
            Ordering::Greater => Err(ParseError::UnexpectedEof),
        }
    }
}

#[derive(Debug)]
pub enum ParseError {
    InvalidStructureSize,
    UnexpectedEof,
    ExcessTrailingBytes,
    ContextNotSupported,
}
