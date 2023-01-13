use std::collections::HashMap;
use dryoc::pwhash;
use crate::client::organization_creation::OrganizationCreationError::{NotEnoughUsersError, PasswordNotStrong, ServerError, ValidationError};
use crate::validation::validate_name;
use zxcvbn::zxcvbn;
use crate::client::key_pair::create_protected_key_pair;
use crate::server_connection::ServerConnection;


pub struct OrganizationBuilder {
    organization_name: String,
    argon_config: pwhash::Config,
    user_credentials: HashMap<String, String>,
}

impl OrganizationBuilder {
    pub fn new(organization_name: &str, argon_config: &pwhash::Config) -> Result<Self, OrganizationCreationError> {
        validate_name(organization_name).map_err(|_| ValidationError)?;
        Ok(Self {
            organization_name: organization_name.to_string(),
            argon_config: argon_config.clone(),
            user_credentials: HashMap::new(),
        })
    }

    pub fn add_user(mut self, username: &str, password: &str) -> Result<Self, OrganizationCreationError> {
        validate_name(username).map_err(|_| ValidationError)?;
        let password_entropy = zxcvbn(password, &[username, &self.organization_name]).map_err(|_| PasswordNotStrong(None))?;

        if password_entropy.score() < 4 {
            Err(PasswordNotStrong(password_entropy.feedback().clone()))
        } else {
            self.user_credentials.insert(username.to_string(), password.to_string());
            Ok(self)
        }
    }

    pub fn create_organization<A: ServerConnection>(self, server: &mut A) -> Result<(), OrganizationCreationError> {
        if self.user_credentials.len() < 2 {
            return Err(NotEnoughUsersError);
        }

        let (encrypted_user_shares, public_key) =
            create_protected_key_pair(&self.user_credentials, &self.argon_config);
        server.create_organization(&self.organization_name, &encrypted_user_shares, &public_key, &self.argon_config)
            .ok_or(ServerError)
    }
}

#[derive(Debug)]
pub enum OrganizationCreationError {
    ValidationError,
    PasswordNotStrong(Option<zxcvbn::feedback::Feedback>),
    NotEnoughUsersError,
    ServerError,
}
