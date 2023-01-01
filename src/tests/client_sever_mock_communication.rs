use std::collections::HashMap;
use crate::client::AuthenticatedClient;
use crate::client_unsealing::PrivateKeyProtection;
use crate::data::DocumentID;
use crate::Document;
use crate::server::Server;


pub(super) fn create_organization(server: &Server, organization_name: &str, user_credentials: &HashMap<String, String>) {
    let private_key_manager = PrivateKeyProtection::new_unsafe();

    let (user_encrypted_shares, public_key) =
        private_key_manager.create_protected_key_pair(&user_credentials);

    server.create_organization(organization_name, &user_encrypted_shares, &public_key).unwrap();
}

pub(super) fn unlock_vault_for_organization(server: &mut Server, organization_name: &str,
                                 username1: &str, password1: &str,
                                 username2: &str, password2: &str)
                                 -> AuthenticatedClient {
    let private_key_manager = PrivateKeyProtection::new_unsafe();

    let (user_share1, user_share2, public_key, encrypted_token) =
        server.unlock_vault(organization_name, username1, username2).unwrap();
    private_key_manager.get_vault_access(
        &encrypted_token, &public_key, password1, &user_share1, password2, &user_share2)
}

pub(super) fn upload(document: &Document, client: &AuthenticatedClient, server: &Server) -> Option<()> {
    let (encrypted_document, encrypted_key) = client.new_document(document);
    server.new_document(&client.token, &encrypted_document, &encrypted_key)
}

pub(super) fn share(document_id: &DocumentID, other_organization_name: &str,
                    client: &AuthenticatedClient, server: &Server) -> Option<()>{
    let encrypted_document_key = server.get_document_key(&client.token, document_id).unwrap();
    let other_organization_public_key = server.get_public_key_of_organization(other_organization_name).unwrap();
    let new_encrypted_document_key = client.add_owner(&encrypted_document_key, &other_organization_public_key);
    server.add_owner(&client.token, &document_id, other_organization_name, &new_encrypted_document_key)
}

pub(super) fn download_from_document_id(document_id: &DocumentID, client: &AuthenticatedClient, server: &Server) -> Document{
    let encrypted_document = server.download_document(&client.token, &document_id).unwrap();
    let document_key = server.get_document_key(&client.token, &document_id).unwrap();
    let document = client.get_document(&encrypted_document, &document_key);

    document
}

pub(super) fn download_from_document_name(document_name: &str, client: &AuthenticatedClient, server: &Server) -> Document {
    let document_list = server.list_documents(&client.token).unwrap();
    let document_id = client.find_document_id_from_name(&document_list, document_name).unwrap();

    download_from_document_id(&document_id, &client, &server)
}

pub(super) fn update(document_id: &DocumentID, new_document: &Document, client: &AuthenticatedClient, server: &Server)
                     -> Option<()> {
    let document_key = server.get_document_key(&client.token, &document_id)?;
    let new_document_encrypted = client.update_document(new_document, &document_key);
    server.update_document(&client.token, &document_id, &new_document_encrypted)
}

pub(super) fn get_id_of_document_by_name(document_name: &str, client: &AuthenticatedClient, server: &Server) -> Option<DocumentID> {
    let document_list = server.list_documents(&client.token).unwrap();
    client.find_document_id_from_name(&document_list, document_name)
}