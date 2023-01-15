use std::collections::HashMap;
use dryoc::pwhash;
use crate::validation::validate_and_standardize_name;
use zxcvbn::zxcvbn;
use crate::client::key_pair::create_protected_key_pair;
use crate::error::VaultError;
use crate::error::VaultError::{NotEnoughUsers, PasswordNotStrong};
use crate::server_connection::ServerConnection;

#[derive(Clone)]
pub struct OrganizationBuilder {
    organization_name: String,
    argon_config: pwhash::Config,
    user_credentials: HashMap<String, String>,
}

impl OrganizationBuilder {
    pub fn new(organization_name: &str, argon_config: &pwhash::Config) -> Result<Self, VaultError> {
        let organization_name= validate_and_standardize_name(organization_name)?;
        Ok(Self {
            organization_name: organization_name.to_string(),
            argon_config: argon_config.clone(),
            user_credentials: HashMap::new(),
        })
    }

    pub fn add_user(mut self, username: &str, password: &str) -> Result<Self, VaultError> {
        let username = validate_and_standardize_name(username)?;
        let password_entropy = zxcvbn(password, &[&username, &self.organization_name]).map_err(|_| PasswordNotStrong(None))?;

        if password_entropy.score() < 4 {
            Err(PasswordNotStrong(None))
        } else {
            self.user_credentials.insert(username.to_string(), password.to_string());
            Ok(self)
        }
    }

    pub fn create_organization<A: ServerConnection>(self, server: &mut A) -> Result<(), VaultError> {
        if self.user_credentials.len() < 2 {
            return Err(NotEnoughUsers);
        }

        let (encrypted_user_shares, public_key) =
            create_protected_key_pair(&self.user_credentials, &self.argon_config)?;
        server.create_organization(&self.organization_name, &encrypted_user_shares, &public_key, &self.argon_config)
    }
}


