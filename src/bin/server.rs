use vault::server::http_server;
use vault::config::SERVER_PORT;

fn main() {
    println!("Hello, server!");

    http_server::run_http_server(SERVER_PORT, "vault-data".into());
}