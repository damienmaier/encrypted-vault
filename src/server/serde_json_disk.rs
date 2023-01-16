//! Provides useful functions for serializing objects and storing them as files on the disk

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use crate::error::VaultError;
use crate::error::VaultError::FileError;

pub fn save<T: ?Sized + Serialize>(value: &T, file_path: &Path, ok_to_overwrite: bool) -> Result<(), VaultError> {
    if !ok_to_overwrite && file_path.exists() {
        return Err(FileError);
    }
    let text = serde_json::to_string(value).map_err(|_| FileError)?;
    fs::create_dir_all(file_path.parent().ok_or(FileError)?).map_err(|_| FileError)?;
    fs::write(file_path, text).map_err(|_| FileError)
}

pub fn load<T: DeserializeOwned>(file_path: &Path) -> Result<T, VaultError> {
    let text = fs::read_to_string(&file_path).map_err(|_| FileError)?;
    serde_json::from_str(&text).map_err(|_| FileError)
}