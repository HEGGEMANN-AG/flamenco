use std::{
    collections::HashMap,
    convert::Infallible,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    ops::{Deref, DerefMut},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use hmac::{Hmac, Mac};
#[cfg(feature = "kenobi")]
use kenobi::{
    client::ClientContext,
    cred::Outbound,
    typestate::{NoEncryption, NoSigning},
};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    access::AccessMask,
    command::Command,
    create::{CreateDisposition, CreateRequest, CreateResponse, OplockLevel, ShareAccess},
    dialect::Dialect,
    header::{FLAG_SIGNED, Flags, Smb2SyncHeader},
    negotiate::{NegotiateRequest, NegotiateResponse},
    security::SecurityMode16,
    tree::{TreeConnectRequest, TreeConnectResponse},
};

mod access;
mod byteorder;
mod command;
mod create;
mod dialect;
mod file;
mod header;
mod negotiate;
mod security;
mod session;
mod tree;

pub const DEFAULT_PORT: u16 = 445;

#[derive(Default)]
pub struct Client {
    connections: Arc<Mutex<HashMap<SocketAddr, Weak<Connection>>>>,
    client_guid: Uuid,
}
impl Client {
    pub fn new() -> std::io::Result<Arc<Self>> {
        let client = Self::default();
        Ok(Arc::new(client))
    }
}
impl Connection {
    pub fn new(client: Arc<Client>, addr: impl ToSocketAddrs + Clone) -> std::io::Result<Arc<Connection>> {
        let socket = addr.to_socket_addrs()?.next().unwrap();
        let tcp = TcpStream::connect(socket)?;
        let tcp = Mutex::new(tcp);
        let mut lock = tcp.lock().unwrap();
        write_tcp_message(
            None::<&Infallible>,
            &Smb2SyncHeader {
                credit_charge: 0,
                status: 0,
                command: Command::Negotiate,
                credit_request_or_response: 32,
                flags: Flags::empty(),
                next_command: None,
                message_id: 0,
                tree_id: 0,
                session_id: 0,
                signature: Default::default(),
            },
            &NegotiateRequest {
                security_mode: SecurityMode16::SIGNING_REQUIRED,
                capabilities: 0x00,
                client_guid: client.client_guid,
                dialects: vec![Dialect::Smb202],
            },
            &mut lock,
        )?;
        let mut new_size = [0u8; 4];
        lock.read_exact(&mut new_size)?;

        let _response_header = Smb2SyncHeader::read_from(&mut lock.deref_mut())?;
        let response_body = NegotiateResponse::read_from(&mut lock)?;
        drop(lock);
        Ok(Arc::new_cyclic(|weak| {
            client.connections.lock().unwrap().insert(socket, weak.clone());
            Connection {
                client,
                sessions: Mutex::default(),
                tcp,
                message_id: AtomicU64::new(1),
                requires_signing: response_body.is_signing_required(),
            }
        }))
    }
}

pub struct Connection {
    client: Arc<Client>,
    sessions: Mutex<HashMap<u64, Weak<Session>>>,
    tcp: Mutex<TcpStream>,
    message_id: AtomicU64,
    requires_signing: bool,
}
impl Connection {
    fn next_message_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
    }
    pub fn get_session(&self, id: u64) -> Option<Arc<Session>> {
        let mut map = self.sessions.lock().unwrap();
        map.remove(&id)?.upgrade().inspect(|undropped| {
            map.insert(id, Arc::downgrade(undropped));
        })
    }
}

pub struct Session {
    connection: Arc<Connection>,
    auth_ctx: Arc<dyn Authentication>,
    tree_connects: Mutex<HashMap<u32, Weak<Tree>>>,
    session_id: u64,
}
pub struct Kenobi(ClientContext<Outbound, NoSigning, NoEncryption>);
pub trait Authentication {
    fn session_key(&self) -> [u8; 16];
    fn verify_signature(&self, message_without_signature: &[u8], signature: &[u8; 16]) -> bool {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.session_key()).unwrap();
        hmac.update(message_without_signature);
        let message_hash = hmac.finalize().into_bytes();
        &message_hash[0..16] == signature
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
impl<T: Deref<Target: Authentication>> Authentication for &T {
    fn session_key(&self) -> [u8; 16] {
        T::Target::session_key(self)
    }
}
#[cfg(feature = "kenobi")]
impl Session {
    pub fn new_kenobi(
        connection: Arc<Connection>,
        principal: Option<&str>,
        target_principal: Option<&str>,
    ) -> std::io::Result<Arc<Session>> {
        use kenobi::{
            client::{ClientBuilder, StepOut},
            cred::Credentials,
        };

        let mut ctx =
            match ClientBuilder::new_from_credentials(Credentials::outbound(principal).unwrap(), target_principal)
                .initialize()
            {
                StepOut::Pending(pending) => pending,
                StepOut::Finished(_) => unreachable!(),
            };
        let mut session_id = 0;
        let mut tcp = connection.tcp.lock().unwrap();
        loop {
            use crate::{
                header::Flags,
                security::SecurityMode8,
                session::{SessionSetupRequest, SessionSetupResponse},
            };

            write_tcp_message(
                None::<&Infallible>,
                &Smb2SyncHeader {
                    credit_charge: 1,
                    status: 0,
                    command: Command::SessionSetup,
                    credit_request_or_response: 32,
                    flags: Flags::empty(),
                    next_command: None,
                    message_id: connection.next_message_id(),
                    tree_id: 0,
                    session_id,
                    signature: Default::default(),
                },
                &SessionSetupRequest {
                    flags: 0,
                    security_mode: SecurityMode8::SIGNING_REQUIRED,
                    capabilities: 0,
                    previous_session_id: 0,
                    security_buffer: ctx.next_token().to_vec().into_boxed_slice(),
                },
                &mut tcp,
            )?;

            let mut new_size = [0u8; 4];
            tcp.read_exact(&mut new_size)?;
            let msg_len = u32::from_be_bytes(new_size) as usize;

            let mut buffer = vec![0; msg_len];
            tcp.read_exact(&mut buffer)?;
            let mut reader = buffer.as_slice();
            let header = Smb2SyncHeader::read_from(&mut reader)?;
            session_id = header.session_id;

            let session_setup_reponse = SessionSetupResponse::read_from(&mut reader)?;

            ctx = match ctx.step(session_setup_reponse.security_token()) {
                StepOut::Pending(pending_client_context) => pending_client_context,
                StepOut::Finished(ctx) => {
                    let auth_ctx = Kenobi(ctx);
                    if header.flags.contains(FLAG_SIGNED) {
                        buffer[48..64].copy_from_slice(&[0u8; 16]);
                        if !auth_ctx.verify_signature(&buffer, &header.signature) {
                            panic!("Invalid session etablish signature");
                        };
                    }

                    let session = Arc::new_cyclic(|weak| {
                        connection.sessions.lock().unwrap().insert(session_id, weak.clone());
                        Session {
                            connection: connection.clone(),
                            tree_connects: Mutex::default(),
                            auth_ctx: Arc::new(auth_ctx),
                            session_id,
                        }
                    });
                    return Ok(session);
                }
            }
        }
    }
}

pub struct Tree {
    session: Arc<Session>,
    tree_id: u32,
}
impl Session {
    pub fn tree_connect(session: Arc<Session>, share_path: &str) -> std::io::Result<Arc<Tree>> {
        let header = Smb2SyncHeader {
            credit_charge: 0,
            status: 0,
            command: Command::TreeConnect,
            credit_request_or_response: 0,
            flags: FLAG_SIGNED,
            next_command: None,
            message_id: session.connection.next_message_id(),
            tree_id: 0,
            session_id: session.session_id,
            signature: Default::default(),
        };
        let msg = TreeConnectRequest::new(share_path);
        let (Smb2SyncHeader { tree_id, .. }, message) = {
            let mut tcp = session.connection.tcp.lock().unwrap();
            let auth = session.auth_ctx.as_ref();
            write_tcp_message(Some(auth), &header, &msg, &mut tcp)?;
            read_tcp_message(auth, &mut tcp)?
        };
        let _response = TreeConnectResponse::read_from(message.as_slice())?;
        Ok(Arc::new_cyclic(|weak| {
            session.tree_connects.lock().unwrap().insert(tree_id, weak.clone());
            Tree { session, tree_id }
        }))
    }
}
impl Tree {
    pub fn create(&self, file_path: &str) -> std::io::Result<CreateResponse> {
        let header = Smb2SyncHeader {
            credit_charge: 0,
            status: 0,
            command: Command::Create,
            credit_request_or_response: 0,
            flags: FLAG_SIGNED,
            next_command: None,
            message_id: self.session.connection.next_message_id(),
            tree_id: self.tree_id,
            session_id: self.session.session_id,
            signature: Default::default(),
        };
        let msg = CreateRequest {
            oplock_level: OplockLevel::None,
            desired_access: AccessMask::new(0x1),
            share_access: ShareAccess::default(),
            create_disposition: CreateDisposition::default(),
            file_name: Some(String::from(file_path)),
        };
        let mut tcp = self.session.connection.tcp.lock().unwrap();
        let auth = self.session.auth_ctx.as_ref();
        write_tcp_message(Some(auth), &header, &msg, &mut tcp)?;

        let (_header, message) = read_tcp_message(auth, &mut tcp)?;
        let response = CreateResponse::read_from(message.as_slice())?;
        Ok(response)
    }
}

fn write_tcp_message<Auth: Authentication + ?Sized, W: Write, M: Smb2ClientMessage>(
    auth: Option<&Auth>,
    header: &Smb2SyncHeader,
    msg: &M,
    writer: &mut impl DerefMut<Target = W>,
) -> std::io::Result<()> {
    let mut message = Vec::with_capacity(64 + msg.size_hint());
    header.write_to(&mut message)?;
    msg.write_to(&mut message)?;
    if let Some(auth) = auth {
        let sig = auth.create_signature(&message);
        message[48..64].copy_from_slice(&sig);
    }

    let len_bytes = (message.len() as u32).to_be_bytes();
    assert_eq!(len_bytes[0], 0);
    writer.write_all(&len_bytes)?;
    writer.write_all(&message)?;
    writer.flush()?;
    Ok(())
}

fn read_tcp_message<A: Authentication + ?Sized, D: DerefMut<Target: Read>>(
    auth: &A,
    tcp: &mut D,
) -> std::io::Result<(Smb2SyncHeader, Vec<u8>)> {
    let mut message_len = [0u8; 4];
    tcp.read_exact(&mut message_len)?;

    let mut buffer = vec![0; u32::from_be_bytes(message_len) as usize];
    tcp.read_exact(&mut buffer)?;
    let mut reader = buffer.as_slice();
    let header = Smb2SyncHeader::read_from(&mut reader)?;
    if header.flags.contains(FLAG_SIGNED) {
        (&mut buffer[48..64]).write_all(&[0; 16]).unwrap();
        if !auth.verify_signature(&buffer, &header.signature) {
            panic!("Invalid signature")
        };
    }
    Ok((header, buffer[64..].to_vec()))
}

trait Smb2ClientMessage {
    fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()>;
    fn size_hint(&self) -> usize;
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "kenobi")]
    fn against_data() {
        use std::env::var;

        use super::DEFAULT_PORT;
        use crate::{Client, Connection, Session};
        let test_server = var("FLAMENCO_TEST_SERVER").unwrap_or(format!("localhost:{DEFAULT_PORT}"));
        let test_spn = var("FLAMENCO_TEST_SPN").ok();
        let test_target_spn = var("FLAMENCO_TEST_TARGET_SPN").ok();
        let tree = var("FLAMENCO_TEST_TREE").unwrap();
        let test_file = var("FLAMENCO_TEST_FILE").unwrap();

        let client = Client::new().unwrap();

        let connection = Connection::new(client.clone(), test_server).unwrap();

        let session = Session::new_kenobi(connection, test_spn.as_deref(), test_target_spn.as_deref()).unwrap();

        let tree = Session::tree_connect(session.clone(), &tree).unwrap();

        let create_response = tree.create(&test_file).unwrap();
        dbg!(create_response);
    }
}
