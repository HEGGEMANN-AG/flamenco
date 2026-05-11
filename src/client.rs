use std::sync::Arc;
use tokio::net::ToSocketAddrs;

use crate::{
    connection::{ConnectError, Connection},
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
}
impl Client {
    pub fn new(requires_signing: bool) -> Arc<Self> {
        Self {
            requires_signing,
            guest_policy: Default::default(),
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
}
