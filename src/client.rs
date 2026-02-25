use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, ToSocketAddrs},
    ops::DerefMut,
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
struct ClientInner(Arc<Mutex<HashMap<Arc<ServerName>, Weak<Connection>>>>);
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
    pub(crate) fn deregister_connection(&self, con: &ServerName) {
        self.connections.0.lock().unwrap().remove(con);
    }
    pub fn connect(&self, addr: impl ToServerName, port: Option<u16>) -> std::io::Result<Arc<Connection>> {
        let server_name = Arc::new(addr.to_server_name());
        let port = port.unwrap_or(445);
        match server_name.as_ref() {
            ServerName::IpAddr(ip_addr) => self.try_connections(server_name.clone(), (*ip_addr, port)),
            ServerName::ServerName(name) => self.try_connections(server_name.clone(), format!("{name}:{port}")),
        }
    }
    fn try_connections(
        &self,
        server_name: Arc<ServerName>,
        sock: impl ToSocketAddrs,
    ) -> std::io::Result<Arc<Connection>> {
        let mut last_error = None;
        let mut connections = self.connections.0.lock().unwrap();
        for socket_addr in sock.to_socket_addrs()? {
            if let Some(con) = connections.get(&server_name).and_then(Weak::upgrade) {
                return Ok(con);
            };
            match Connection::new(self.clone(), socket_addr, server_name.clone())
                .map(Arc::new)
                .and_then(|arc| {
                    register_connection(&server_name, Arc::downgrade(&arc), connections.deref_mut())?;
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

fn register_connection(
    server_name: &Arc<ServerName>,
    connection: Weak<Connection>,
    s: &mut HashMap<Arc<ServerName>, Weak<Connection>>,
) -> std::io::Result<()> {
    if s.insert(server_name.clone(), connection).is_some() {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "Connection to this server already exists",
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServerName {
    IpAddr(IpAddr),
    ServerName(String),
}
pub trait ToServerName: Clone {
    fn to_server_name(&self) -> ServerName;
}
impl ToServerName for &str {
    fn to_server_name(&self) -> ServerName {
        ServerName::ServerName(self.to_string())
    }
}
impl ToServerName for IpAddr {
    fn to_server_name(&self) -> ServerName {
        ServerName::IpAddr(*self)
    }
}
