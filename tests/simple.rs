use std::sync::Arc;

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
    let con = client.connect(server_copy).await.unwrap();
    let session = Session202::new(con, credentials, target_spn.as_deref())
        .await
        .unwrap();
    let tree = TreeConnection::new(session.clone(), &share_path)
        .await
        .unwrap();
    let mut file = tree.clone().open_file(&file_path).await.unwrap();
    eprintln!("Opened file");
    let mut s = String::new();
    file.read_to_string(&mut s).await.unwrap();
    file.close().await.unwrap();
    Arc::into_inner(tree).unwrap().disconnect().await;
    Arc::into_inner(session).unwrap().logoff().await;
    println!("Read file: {s}");
}
