use std::{io::Read, time::Duration};

use flamenco::{client::Client202, session::Session202, tree::TreeConnection};
use kenobi::cred::Credentials;

#[test]
fn main() {
    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let file_path = std::env::var("FLAMENCO_TEST_FILE").unwrap();
    let client = Client202::new(true);
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let server_copy = server.clone();
    let con = client.connect(server_copy).unwrap();
    let con_copy = con.clone();
    let tspn_clone = target_spn.clone();
    let share_path_copy = share_path.clone();
    let file_path_copy = file_path.clone();
    let t = std::thread::spawn(move || {
        let credentials = Credentials::new(own_spn.as_deref()).unwrap();
        let session = Session202::new(con_copy, &credentials, tspn_clone.as_deref()).unwrap();
        let tree = TreeConnection::new(session, &share_path_copy).unwrap();
        let mut file = tree.open_file(&file_path_copy).unwrap();
        let mut str = String::new();
        file.read_to_string(&mut str).unwrap();
        println!("Read from side thread: {str}");
        std::thread::sleep(Duration::from_secs(1));
    });
    let other_session = Session202::new(con, &credentials, target_spn.as_deref()).unwrap();
    let other_tree = TreeConnection::new(other_session, &share_path).unwrap();
    let mut file2 = other_tree.open_file(&file_path).unwrap();
    let mut s = String::new();
    file2.read_to_string(&mut s).unwrap();
    println!("Read from main thread: {s}");
    std::thread::sleep(Duration::from_secs(1));
    t.join().unwrap();
}
