use std::{convert::Infallible, ops::Deref};

use hmac::{Hmac, Mac};
use kenobi::client::ClientContext;
use sha2::Sha256;

use crate::Kenobi;

pub trait Authentication: Sync + Send {
    fn session_key(&self) -> [u8; 16];
    fn verify_signature(&self, message_buffer: &mut [u8]) -> bool {
        let signature: [u8; 16] = *message_buffer[48..64].as_array().unwrap();
        message_buffer[48..64].copy_from_slice(&[0; 16]);
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.session_key()).unwrap();
        hmac.update(message_buffer);
        let message_hash = hmac.finalize().into_bytes();
        message_hash[0..16] == signature
    }
    fn create_signature(&self, message_without_signature: &[u8]) -> [u8; 16] {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.session_key()).unwrap();
        hmac.update(message_without_signature);
        hmac.finalize().into_bytes()[..16].try_into().unwrap()
    }
}

impl Authentication for Infallible {
    fn session_key(&self) -> [u8; 16] {
        unreachable!()
    }
}
impl Authentication for Kenobi {
    fn session_key(&self) -> [u8; 16] {
        let raw_key = ClientContext::session_key(&self.0);
        raw_key[0..16].try_into().unwrap()
    }
}
impl<T: Deref<Target: Authentication> + Sync> Authentication for &T {
    fn session_key(&self) -> [u8; 16] {
        T::Target::session_key(self)
    }
}
