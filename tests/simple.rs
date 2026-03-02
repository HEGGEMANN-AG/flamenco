use kenobi::cred::Credentials;

#[test]
fn main() {
    use std::time::Duration;

    use flamenco::client::Client202;

    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let own_spn = std::env::var("FLAMENCO_TEST_SPN").ok();
    let target_spn = std::env::var("FLAMENCO_TEST_TARGET_SPN").ok();
    let share_path = std::env::var("FLAMENCO_TEST_SHARE_PATH").unwrap();
    let client = Client202::new(true);
    let credentials = Credentials::new(own_spn.as_deref()).unwrap();
    let mut con = client.connect(server).unwrap();
    let mut session = con
        .setup_session(&credentials, target_spn.as_deref())
        .unwrap();
    let mut tree = session.tree_connect(&share_path).unwrap();
    let _file = tree.open_file("21_Softwareentwicklung\\smb-test.txt");
    std::thread::sleep(Duration::from_millis(200));
}
