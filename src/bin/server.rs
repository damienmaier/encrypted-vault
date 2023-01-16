use std::path::PathBuf;
use vault::server::http_server;
use vault::server::server_config::ServerConfig;

fn main() {
    let server_port = ServerConfig::get().server_port;

    println!("Server listening on port {server_port}");
    http_server::run_http_server(server_port, PathBuf::from("vault-data"));
}