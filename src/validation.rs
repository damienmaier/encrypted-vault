use crate::error::VaultError;
use crate::error::VaultError::ValidationError;

pub fn validate_and_standardize_name(name: &str) -> Result<String, VaultError> {
    if name.len() < 1 || name.len() > 100 || !name.chars().all(|c|c.is_ascii_alphanumeric()){
        Err(ValidationError)
    } else{
        Ok(name.to_lowercase())
    }
}