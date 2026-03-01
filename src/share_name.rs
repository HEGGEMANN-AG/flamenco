const SHARE_NAME_ILLEGAL_CHARACTERS: &[char] = &[
    '"', '/', '\\', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '*', '?',
];

#[derive(Clone, Debug)]
pub struct ShareName(String);
impl ShareName {
    pub fn new(s: &str) -> Result<Self, InvalidShareName> {
        match validate_share_name(s) {
            Ok(()) => Ok(Self(s.to_string())),
            Err(e) => Err(e),
        }
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn validate_share_name(s: &str) -> Result<(), InvalidShareName> {
    s.chars()
        .try_fold(0usize, |count, next_char| match next_char {
            c if SHARE_NAME_ILLEGAL_CHARACTERS.contains(&c) => {
                Err(InvalidShareName::InvalidCharacter(c))
            }
            c if ('\0'..='\u{1F}').contains(&c) => Err(InvalidShareName::InvalidControlCharacter),
            _ if count > 80 => Err(InvalidShareName::TooLong),
            _ => Ok(count + 1),
        })?;
    Ok(())
}
#[derive(Debug)]
pub enum InvalidShareName {
    TooLong,
    InvalidCharacter(char),
    InvalidControlCharacter,
}
