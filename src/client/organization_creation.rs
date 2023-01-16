//! Provides functions that must be called from the user interface to create an organization

use std::collections::HashMap;
use std::time::Instant;

use dryoc::pwhash;
use dryoc::pwhash::VecPwHash;
use zxcvbn::zxcvbn;

use crate::client::key_pair::create_protected_key_pair;
use crate::error::VaultError;
use crate::error::VaultError::{CryptographyError, NotEnoughUsers, PasswordNotStrong};
use crate::server_connection::ServerConnection;
use crate::validation::validate_and_standardize_name;

/// Used to prepare the data needed to create an organization and to send it to the server.
/// 
/// Once an instance of OrganizationBuilder is created, at least two users must be added by calling add_user.
/// The organization request can then be sent to the server with create_organization.
#[derive(Clone)]
pub struct OrganizationBuilder {
    organization_name: String,
    argon_config: pwhash::Config,
    user_credentials: HashMap<String, String>,
}

impl OrganizationBuilder {
    pub fn new(organization_name: &str, argon_config: &pwhash::Config) -> Result<Self, VaultError> {
        let organization_name = validate_and_standardize_name(organization_name)?;
        Ok(Self {
            organization_name: organization_name.to_string(),
            argon_config: argon_config.clone(),
            user_credentials: HashMap::new(),
        })
    }

    /// Adds a user and its password.
    /// 
    /// If the user password is not strong enough, a PasswordNotStrong error is returned, with an optional text providing useful information to improve the password.
    pub fn add_user(mut self, username: &str, password: &str) -> Result<Self, VaultError> {
        let username = validate_and_standardize_name(username)?;
        let password_entropy = zxcvbn(password, &[&username, &self.organization_name]).map_err(|_| PasswordNotStrong(None))?;

        if password_entropy.score() < 4 {
            Err(password_entropy.feedback().into())
        } else {
            self.user_credentials.insert(username.to_string(), password.to_string());
            Ok(self)
        }
    }

    /// Creates the organization key pair, protects the private key with the user passwords and sends an organization creation request to the server.
    pub fn create_organization<A: ServerConnection>(self, server: &mut A) -> Result<(), VaultError> {
        if self.user_credentials.len() < 2 {
            return Err(NotEnoughUsers);
        }

        let (encrypted_user_shares, public_key) =
            create_protected_key_pair(&self.user_credentials, &self.argon_config)?;
        server.create_organization(&self.organization_name, &encrypted_user_shares, &public_key, &self.argon_config)
    }
}

/// Automatically chooses an Argon2 computation cost such that computing a hash takes at least 10 seconds.
/// 
/// Returns an Argon2 config based on `argon_memlimit_kb` and the chosen computation time.
pub fn empirically_choose_argon_config(argon_memlimit_kb: usize) -> Result<pwhash::Config, VaultError> {
    for iteration_cost in (0..100).map(|exponent| 1.5f32.powi(exponent) as u64) {
        let argon_config = pwhash::Config::interactive()
            .with_memlimit(argon_memlimit_kb)
            .with_opslimit(iteration_cost);

        println!("Testing iteration cost {iteration_cost}...");

        let start_time = Instant::now();
        VecPwHash::hash(&"testPassword1234".as_bytes(), argon_config.clone())
            .map_err(|_| CryptographyError)?;
        let hashing_duration = start_time.elapsed().as_secs();

        println!("Hashing took {hashing_duration} seconds");

        if hashing_duration >= 10 {
            return Ok(argon_config);
        }
    }
    Err(CryptographyError)
}

