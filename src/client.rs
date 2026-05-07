use std::sync::{Arc, atomic::AtomicU16};
use tokio::net::ToSocketAddrs;

use crate::{
    connection::{ConnectError, Connection},
    negotiate::Dialect,
    sign::SecurityMode,
};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum GuestPolicy {
    #[default]
    Disallowed,
    Allowed,
    AllowedInsecurely,
}

#[derive(Debug)]
pub struct Client {
    pub requires_signing: bool,
    pub guest_policy: GuestPolicy,
    pub maximum_compatibility: ClientCompat,
}
impl Client {
    pub fn new_202(requires_signing: bool) -> Arc<Self> {
        Self {
            requires_signing,
            guest_policy: Default::default(),
            maximum_compatibility: ClientCompat::Smb202,
        }
        .into()
    }
    pub fn new_210(requires_signing: bool) -> Arc<Self> {
        Self {
            requires_signing,
            guest_policy: Default::default(),
            maximum_compatibility: ClientCompat::Smb210 {
                credits: AtomicU16::new(0),
            },
        }
        .into()
    }
    pub(crate) fn sent_security_mode(&self) -> SecurityMode {
        if self.requires_signing {
            SecurityMode::SigningRequired
        } else {
            SecurityMode::SigningEnabled
        }
    }
    /// Starts a connection to a server
    ///
    /// Returns a new opening Connection handle and the future that drives the connection.
    /// The connection must only be awaited until after the driving future has been started, otherwise this will deadlock.
    pub async fn connect(
        self: &Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<
        (
            impl Future<Output = Result<Arc<Connection>, ConnectError>>,
            impl Future<Output = ()> + Send + 'static,
        ),
        std::io::Error,
    > {
        Connection::new(self, addr).await
    }

    pub fn supports_multi_credit(&self) -> bool {
        match &self.maximum_compatibility {
            ClientCompat::Smb202 => false,
            ClientCompat::Smb210 { .. } => true,
        }
    }
}

#[derive(Debug)]
pub enum ClientCompat {
    Smb202,
    Smb210 { credits: AtomicU16 },
}
impl ClientCompat {
    pub fn dialect(&self) -> Dialect {
        match self {
            Self::Smb202 => Dialect::SMB2020,
            ClientCompat::Smb210 { .. } => Dialect::SMB21,
        }
    }
}
