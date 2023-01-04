use std::fs;
use std::path::Path;

use serde:: Serialize;
use serde::de::DeserializeOwned;

pub fn save<T: ?Sized + Serialize>(value: &T, file_path: &Path, ok_to_overwrite: bool) -> Option<()> {
    if !ok_to_overwrite && file_path.exists(){
        return None;
    }
    let text = serde_json::to_string(value).ok()?;
    fs::create_dir_all(file_path.parent()?).ok()?;
    fs::write(file_path, text).ok()
}

pub fn load<T: DeserializeOwned>(file_path: &Path) -> Option<T> {
    let text = fs::read_to_string(&file_path).ok()?;
    serde_json::from_str(&text).ok()
}