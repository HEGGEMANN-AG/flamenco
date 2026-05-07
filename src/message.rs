use std::fmt::Debug;

#[derive(Debug)]
pub enum ReadError {
    InvalidNetbiosLength,
    InvalidlySignedMessage,
    Connection(std::io::Error),
}

#[derive(Debug)]
pub enum WriteError {
    Connection(std::io::Error),
    NotEnoughCredits,
    MessageTooLong,
}

pub(crate) trait MessageBody {
    fn write_to(&self, w: &mut Vec<u8>);
    fn size_hint(&self) -> usize {
        0
    }
    fn send_payload_size(&self) -> u32;
    fn expected_response_payload_size(&self) -> u32;
    fn calculate_credits(&self) -> u16 {
        (1 + (self
            .send_payload_size()
            .max(self.expected_response_payload_size())
            .saturating_sub(1))
            / 65536) as u16
    }
}
