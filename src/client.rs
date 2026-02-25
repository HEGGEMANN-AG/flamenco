use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, Weak},
};

use uuid::Uuid;

use crate::Connection;

#[derive(Clone, Default)]
pub struct Client {
    connections: ClientInner,
    client_guid: Uuid,
}
#[derive(Default)]
struct ClientInner(Arc<Mutex<HashMap<SocketAddr, Weak<Connection>>>>);
impl Clone for ClientInner {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl Client {
    pub fn new() -> Self {
        Self::default()
    }
    pub(crate) fn client_id(&self) -> Uuid {
        self.client_guid
    }
    fn register_connection(&self, con: SocketAddr, connection: Weak<Connection>) -> std::io::Result<()> {
        if self.connections.0.lock().unwrap().insert(con, connection).is_some() {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "Connection to this server already exists",
            ))
        } else {
            Ok(())
        }
    }
    pub(crate) fn deregister_connection(&self, con: SocketAddr) {
        self.connections.0.lock().unwrap().remove(&con);
    }
    pub fn connect(&self, addr: impl ToSocketAddrs + Clone) -> std::io::Result<Arc<Connection>> {
        let mut last_error = None;
        let connections = self.connections.0.lock().unwrap();
        for socket_addr in addr.to_socket_addrs()? {
            if let Some(con) = connections.get(&socket_addr).and_then(Weak::upgrade) {
                return Ok(con);
            };
            match Connection::new(self.clone(), socket_addr)
                .map(Arc::new)
                .and_then(|arc| {
                    self.register_connection(socket_addr, Arc::downgrade(&arc))?;
                    Ok(arc)
                }) {
                Ok(val) => return Ok(val),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "did not resolve to any input")))
    }
}
