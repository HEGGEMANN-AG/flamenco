use std::sync::Arc;

use flamenco::{
    client::Client202,
    file::{AccessMask, CreateDisposition},
    session::Session202,
    tree::{Tree, TreeConnection},
};
use kenobi::{cred::Credentials, mech::Mechanism};
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread")]
async fn main() {
    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let file_path = std::env::var("FLAMENCO_TEST_FILE").unwrap();
    let client = Client202::new(true);
    let credentials = Credentials::outbound(own_spn.as_deref(), Mechanism::Spnego).unwrap();
    let server_copy = server.clone();
    let (con, drive) = client.connect(server_copy).await.unwrap();
    tokio::spawn(drive);
    let con = con.await.unwrap();
    let session = Session202::new(con, credentials, target_spn.as_deref()).await.unwrap();
    let tree = TreeConnection::new(session.clone(), &share_path)
        .await
        .unwrap()
        .to_disk()
        .unwrap();
    let tree = Arc::new(tree);
    let mut file = tree
        .open_file(
            &file_path,
            AccessMask::READ_ATTRIBUTES | AccessMask::READ_DATA,
            CreateDisposition::default(),
        )
        .await
        .unwrap()
        .0;
    eprintln!("Opened file");
    let mut s = String::new();
    file.read_to_string(&mut s).await.unwrap();
    file.close().await.unwrap();
    Arc::into_inner(tree).unwrap().disconnect().await;
    Arc::into_inner(session).unwrap().logoff().await;
    println!("Read file: {s}");
}
