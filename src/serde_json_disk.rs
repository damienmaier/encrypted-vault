use std::fs;
use std::path::Path;

use serde:: Serialize;
use serde::de::DeserializeOwned;

pub(crate) fn save<T: ?Sized + Serialize>(value: &T, file_path: &Path) -> Option<()> {
    let text = serde_json::to_string(value).ok()?;
    fs::create_dir_all(file_path.parent()?).ok()?;
    fs::write(file_path, text).ok()
}

pub(crate) fn load<T: DeserializeOwned>(file_path: &Path) -> Option<T> {
    let text = fs::read_to_string(&file_path).ok()?;
    serde_json::from_str(&text).ok()
}