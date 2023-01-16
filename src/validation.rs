use crate::error::VaultError;
use crate::error::VaultError::ValidationError;

/// Validates that a name is only alphanumerical and has a length between 1 and 100.
/// Returns a lowercase version of the name.
///
/// After a name is validated, only the "standard" lowercase version returned by this function must be used
pub fn validate_and_standardize_name(name: &str) -> Result<String, VaultError> {
    if name.len() < 1 || name.len() > 100 || !name.chars().all(|c|c.is_ascii_alphanumeric()){
        Err(ValidationError)
    } else{
        Ok(name.to_lowercase())
    }
}