use std::{fs, io};
use std::path::PathBuf;

pub fn get_certificate_der_from_pem_file(pem_file_path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    let mut certificates = rustls_pemfile::certs(
        &mut fs::read(pem_file_path)?.as_slice()
    )?;
    // remove and not get because we want to get an owned value, not a reference
    Ok(certificates.remove(0))
}

pub fn get_key_der_from_pem_file(pem_file_path: &PathBuf) -> Result<Vec<u8>, io::Error>  {
    let mut keys = rustls_pemfile::pkcs8_private_keys(
        &mut fs::read(pem_file_path)?.as_slice()
    )?;
    // remove and not get because we want to get an owned value, not a reference
    Ok(keys.remove(0))
}