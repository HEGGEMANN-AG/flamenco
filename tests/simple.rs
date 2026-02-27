#[test]
fn main() {
    use std::time::Duration;

    use flamenco::client::Client202;

    let server = std::env::var("FLAMENCO_TEST_SERVER").unwrap();
    let client = Client202::new();
    let _con = client.connect(server);
    std::thread::sleep(Duration::from_millis(200));
}
