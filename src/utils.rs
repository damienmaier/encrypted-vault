use std::fs;
use std::path::PathBuf;

pub fn get_certificate_der_from_pem_file(pem_file_path: &PathBuf) -> Vec<u8> {
    let data = fs::read(pem_file_path).unwrap();
    let mut certificate_file_content = data.as_slice();
    let mut certificates = rustls_pemfile::certs(&mut certificate_file_content).unwrap();
    certificates.remove(0)
}

pub fn get_key_der_from_pem_file(pem_file_path: &PathBuf) -> Vec<u8> {
    let data = fs::read(pem_file_path).unwrap();
    let mut key_file_content = data.as_slice();
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file_content).unwrap();
    keys.remove(0)
}