use std::collections::HashMap;
use dryoc::dryocbox;
use crate::client_encryptor_decryptor::ClientEncryptorDecryptor;
use crate::client_unsealing::{create_protected_key_pair_unsafe, retrieve_private_key_unsafe};
use crate::data::{DocumentID, Token};
use crate::Document;
use crate::server::Server;


pub(super) fn create_organization(server: &Server, organization_name: &str, user_credentials: &HashMap<String, String>) {
    let (user_encrypted_shares, public_key) =
        create_protected_key_pair_unsafe(&user_credentials);

    server.create_organization(organization_name, &user_encrypted_shares, &public_key).unwrap();
}

pub(super) fn unlock_vault_for_organization(server: &mut Server, organization_name: &str,
                                            username1: &str, password1: &str,
                                            username2: &str, password2: &str)
                                            -> (ClientEncryptorDecryptor, Token) {

    let (user_share1, user_share2, public_key, encrypted_token) =
        server.unlock_vault(organization_name, username1, username2).unwrap();
    let private_key = retrieve_private_key_unsafe(password1, &user_share1, password2, &user_share2);

    let key_pair = dryocbox::KeyPair { public_key, secret_key: private_key };
    let token = encrypted_token.unseal_to_vec(&key_pair).unwrap();

    (ClientEncryptorDecryptor{key_pair}, token)
}

pub(super) fn upload(document: &Document, token: &Token, client: &ClientEncryptorDecryptor, server: &Server) -> Option<()> {
    let (encrypted_document, encrypted_key) = client.generate_document_key_and_encrypt_document(document);
    server.new_document(token, &encrypted_document, &encrypted_key)
}

pub(super) fn share(document_id: &DocumentID, other_organization_name: &str,
                    token: &Token, client: &ClientEncryptorDecryptor, server: &Server) -> Option<()> {
    let encrypted_document_key = server.get_document_key(token, document_id).unwrap();
    let other_organization_public_key = server.get_public_key_of_organization(other_organization_name).unwrap();
    let new_encrypted_document_key = client.encrypt_document_key_for_other_organization(&encrypted_document_key, &other_organization_public_key);
    server.add_owner(token, &document_id, other_organization_name, &new_encrypted_document_key)
}

pub(super) fn download_from_document_id(document_id: &DocumentID, token: &Token, client: &ClientEncryptorDecryptor, server: &Server) -> Document {
    let encrypted_document = server.download_document(token, &document_id).unwrap();
    let document_key = server.get_document_key(token, &document_id).unwrap();
    let document = client.decrypt_document(&encrypted_document, &document_key);

    document
}

pub(super) fn download_from_document_name(document_name: &str, token: &Token, client: &ClientEncryptorDecryptor, server: &Server) -> Document {
    let document_list = server.list_documents(token).unwrap();
    let document_id = client.find_document_id_from_name(&document_list, document_name).unwrap();

    download_from_document_id(&document_id, token, &client, &server)
}

pub(super) fn update(document_id: &DocumentID, new_document: &Document, token: &Token, client: &ClientEncryptorDecryptor, server: &Server)
                     -> Option<()> {
    let document_key = server.get_document_key(token, &document_id)?;
    let new_document_encrypted = client.encrypt_document_with_key(new_document, &document_key);
    server.update_document(token, &document_id, &new_document_encrypted)
}

pub(super) fn get_id_of_document_by_name(document_name: &str, token: &Token, client: &ClientEncryptorDecryptor, server: &Server) -> Option<DocumentID> {
    let document_list = server.list_documents(token).unwrap();
    client.find_document_id_from_name(&document_list, document_name)
}