//! Client configuration
//!
//! The configuration is read from a config file.
//! If the file does not exist, a config file with default values is automatically created.

use std::path::PathBuf;
use confy;
use serde::{Serialize, Deserialize};

pub const SERVER_FILES_LOCATION: &str = "server_files";

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server_port: 1234,
        }
    }
}

impl ServerConfig{
    pub fn get() -> Self{
        confy::load_path(PathBuf::from(SERVER_FILES_LOCATION).join("config"))
            .expect("Could not read server config file")
    }
}
