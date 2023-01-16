use vault::server::http_server;
use vault::server::server_config::ServerConfig;

fn main() {
    println!("Hello, server!");

    http_server::run_http_server(ServerConfig::get().server_port, "vault-data".into());
}