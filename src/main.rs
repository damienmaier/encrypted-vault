use std::fs;
use dryoc::dryocsecretbox::NewByteArray;
use crate::data::{Document, EncryptedDocument};

mod client_encryptor_decryptor;
mod client_unsealing;
mod symmetric_encryption_helper;
mod data;
mod server;
mod tests;
mod serde_json_disk;


fn main() {
    println!("Hello, world!");

    let my_document = data::Document { name: String::from("bonjour"), content: "salut".to_string() };

    let key = dryoc::dryocsecretbox::Key::gen();
    let text = serde_json::to_string(&my_document.encrypt(&key)).unwrap();

    match fs::write("file", text){
        Ok(_) => {}
        Err(_) => {println!("Error")}
    }

    let read_text = fs::read_to_string("file").unwrap();
    let read_ecn_document: EncryptedDocument = serde_json::from_str(&read_text).unwrap();
    let read_document = read_ecn_document.decrypt(&key);

    println!("{read_document:?}");
}
