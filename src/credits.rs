use std::sync::atomic::AtomicU16;

#[derive(Debug)]
pub enum Credits {
    Simple(AtomicU16),
    Multi(AtomicU16),
}
