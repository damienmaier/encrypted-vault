use std::path::PathBuf;
use confy;
use serde::{Serialize, Deserialize};

pub const CLIENT_FILES_LOCATION: &str = "client_files";

#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_hostname: String,
    pub server_port: u16,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_hostname: "localhost".to_string(),
            server_port: 1234,
        }
    }
}

impl ClientConfig{
    pub fn get() -> Self{
        confy::load_path(PathBuf::from(CLIENT_FILES_LOCATION).join("config"))
            .expect("Could not read client config file")
    }
}
