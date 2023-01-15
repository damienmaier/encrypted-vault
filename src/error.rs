
#[derive(Debug, PartialEq)]
pub enum VaultError{
    ServerError,
    FileError,
    ValidationError,
    PasswordNotStrong(Option<String>),
    NotEnoughUsers,
    DocumentNotFound,
    CryptographyError
}
