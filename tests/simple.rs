use std::{sync::Arc, time::Duration};

use flamenco::{
    client::{Client202, SharedConnection},
    session::Session202,
    tree::TreeConnection,
};
use kenobi::cred::Credentials;

#[test]
fn main() {
    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let file_path = std::env::var("FLAMENCO_TEST_FILE").unwrap();
    let client = Arc::new(Client202::new(true));
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let client_ref = client.clone();
    let server_copy = server.clone();
    let con: Arc<_> = SharedConnection::new(client_ref, server_copy)
        .unwrap()
        .into();
    let con_copy = con.clone();
    let tspn_clone = target_spn.clone();
    let share_path_copy = share_path.clone();
    let file_path_copy = file_path.clone();
    let t = std::thread::spawn(move || {
        let credentials = Credentials::new(own_spn.as_deref()).unwrap();
        let session = Session202::new(con_copy, &credentials, tspn_clone.as_deref()).unwrap();
        let tree = TreeConnection::new(session, &share_path_copy).unwrap();
        let file = tree.open_file(&file_path_copy).unwrap();
        std::thread::sleep(Duration::from_secs(1));
    });
    let other_session = Session202::new(con, &credentials, target_spn.as_deref()).unwrap();
    let other_tree = TreeConnection::new(&other_session, &share_path).unwrap();
    let file2 = other_tree.open_file(&file_path).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    t.join().unwrap();
}
