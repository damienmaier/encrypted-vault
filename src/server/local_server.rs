use std::collections::HashMap;
use std::fs;
use std::fs::DirEntry;
use std::path::PathBuf;

use data_encoding::BASE32;
use dryoc::{dryocbox, pwhash, rng};
use dryoc::dryocbox::DryocBox;

use crate::data::{DOCUMENT_ID_LENGTH_BYTES, DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::data::EncryptedDocument;
use crate::error::VaultError;
use crate::error::VaultError::ServerError;
use crate::server::serde_json_disk::{load, save};
use crate::server::session_manager::SessionManager;
use crate::server_connection::ServerConnection;
use crate::validation::validate_and_standardize_name;


pub struct LocalServer {
    data_path: PathBuf,
    sessions: SessionManager,
}

const ORGANIZATIONS_FOLDER_NAME: &str = "organizations";
const PUBLIC_KEY_FILE_NAME: &str = "public_key";
const ARGON_CONFIG_FILE_NAME: &str = "argon_config";
const USERS_FOLDER_NAME: &str = "users";
const DOCUMENTS_KEYS_FOLDER_NAME: &str = "documents_keys";
const DOCUMENTS_FOLDER_NAME: &str = "documents";

const SESSION_TIMEOUT: u64 = 300;

impl LocalServer {
    pub fn new(data_path: &PathBuf) -> LocalServer {
        LocalServer { data_path: data_path.clone(), sessions: SessionManager::new(SESSION_TIMEOUT) }
    }

    fn organization_directory(&self, organization_name: &str) -> PathBuf {
        self.data_path.as_path().join(ORGANIZATIONS_FOLDER_NAME).join(organization_name)
    }

    fn organization_public_key_path(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(PUBLIC_KEY_FILE_NAME)
    }

    fn organization_argon_config_path(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(ARGON_CONFIG_FILE_NAME)
    }

    fn organization_users_directory(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(USERS_FOLDER_NAME)
    }

    fn user_file_path(&self, organization_name: &str, username: &str) -> PathBuf {
        self.organization_users_directory(organization_name).join(username)
    }

    fn organization_document_keys_directory(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(DOCUMENTS_KEYS_FOLDER_NAME)
    }

    fn organization_document_key_path(&self, organization_name: &str, document_id: &DocumentID) -> PathBuf {
        self.organization_document_keys_directory(organization_name).join(BASE32.encode(document_id))
    }

    fn document_path(&self, document_id: &DocumentID) -> PathBuf {
        self.data_path.as_path().join(DOCUMENTS_FOLDER_NAME).join(BASE32.encode(document_id))
    }


    fn is_client_owner_of_document(&self, organization_name: &str, document_id: &DocumentID) -> Result<bool, VaultError> {
        Ok(
            // We check that there is a file whose name matches `document_id`
            // in the folder where the file keys of the organization are stored.
            fs::read_dir(self.organization_document_keys_directory(&organization_name))
                .map_err(|_| ServerError)?
                .filter_map(|dir_entry_result| dir_entry_result.ok())
                .filter_map(|dir_entry| dir_entry.file_name().into_string().ok())
                .any(|file_name| file_name == BASE32.encode(document_id))
        )
    }
}

impl ServerConnection for LocalServer {
    fn create_organization(&mut self,
                           organization_name: &str,
                           users_data: &HashMap<String, UserShare>,
                           public_key: &dryocbox::PublicKey,
                           argon2_config: &pwhash::Config,
    )
                           -> Result<(), VaultError>
    {
        let organization_name = validate_and_standardize_name(organization_name)?;
        if users_data.len() < 2 {
            return Err(ServerError);
        }
        let mut validated_users_data = HashMap::new();
        for (user_name, user_share) in users_data {
            validated_users_data.insert(validate_and_standardize_name(user_name)?, user_share);
        }

        save(public_key, &self.organization_public_key_path(&organization_name), false)?;
        save(argon2_config, &self.organization_argon_config_path(&organization_name), false)?;
        for (user_name, user_share) in validated_users_data {
            save(user_share, &self.user_file_path(&organization_name, &user_name), false)?;
        }
        fs::create_dir_all(self.organization_document_keys_directory(&organization_name)).map_err(|_| ServerError)?;
        Ok(())
    }

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Result<(UserShare, UserShare, pwhash::Config, dryocbox::PublicKey, EncryptedToken), VaultError> {
        let organization_name = validate_and_standardize_name(organization_name)?;
        let user_name1 = validate_and_standardize_name(user_name1)?;
        let user_name2 = validate_and_standardize_name(user_name2)?;

        let public_key: dryocbox::PublicKey = load(&self.organization_public_key_path(&organization_name))?;
        let argon_config: pwhash::Config = load(&self.organization_argon_config_path(&organization_name))?;

        let user_share1: UserShare = load(&self.user_file_path(&organization_name, &user_name1))?;
        let user_share2: UserShare = load(&self.user_file_path(&organization_name, &user_name2))?;

        let token = self.sessions.new_session(&organization_name);
        let encrypted_token = DryocBox::seal_to_vecbox(&token, &public_key).map_err(|_| ServerError)?;

        Ok((user_share1, user_share2, argon_config, public_key, encrypted_token))
    }

    fn revoke_user(&mut self, token: &Token, user_name: &str) -> Result<(), VaultError> {
        let user_name = validate_and_standardize_name(user_name)?;

        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        if fs::read_dir(self.organization_users_directory(&organization_name)).map_err(|_| ServerError)?.count() == 2 {
            return Err(ServerError);
        }

        fs::remove_file(&self.user_file_path(&organization_name, &user_name)).map_err(|_| ServerError)
    }

    fn revoke_token(&mut self, token: &Token) -> Result<(), VaultError> {
        self.sessions.end_session(token);
        Ok(())
    }

    fn new_document(&mut self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey)
                    -> Result<(), VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        let document_id = &rng::randombytes_buf(DOCUMENT_ID_LENGTH_BYTES);

        save(encrypted_document, &self.document_path(&document_id), false)?;
        save(encrypted_key, &self.organization_document_key_path(&organization_name, &document_id), false)?;

        Ok(())
    }

    fn list_documents(&mut self, token: &Token) -> Result<Vec<(DocumentID, EncryptedDocumentNameAndKey)>, VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;

        let build_data = |dir_entry: DirEntry| -> Result<(DocumentID, EncryptedDocumentNameAndKey), VaultError> {
            let document_id_os_str = dir_entry.file_name();
            let document_id = BASE32.decode(document_id_os_str.to_str().ok_or(ServerError)?.as_bytes()).map_err(|_| ServerError)?;
            let encrypted_document: EncryptedDocument = load(&self.document_path(&document_id))?;
            let encrypted_key = load(&self.organization_document_key_path(&organization_name, &document_id))?;

            Ok((document_id, EncryptedDocumentNameAndKey { data: encrypted_document.name, key: encrypted_key }))
        };

        fs::read_dir(self.organization_document_keys_directory(&organization_name)).map_err(|_| ServerError)?
            // filter out dir entries that are error
            .filter_map(|dir_entry_result_result| dir_entry_result_result.ok())
            // filter out dir entries that are not a file
            .filter(|dir_entry| {
                if let Ok(entry_type) = dir_entry.file_type() {
                    entry_type.is_file()
                } else {
                    false
                }
            })
            .map(build_data)
            .collect()
    }

    fn get_document_key(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocumentKey, VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        load(&self.organization_document_key_path(&organization_name, &document_id))
    }

    fn get_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<EncryptedDocument, VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        if self.is_client_owner_of_document(&organization_name, &document_id)? {
            load(&self.document_path(&document_id))
        } else {
            Err(ServerError)
        }
    }

    fn update_document(&mut self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                       -> Result<(), VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        if self.is_client_owner_of_document(&organization_name, &document_id)? {
            save(encrypted_document, &self.document_path(&document_id), true)
        } else {
            Err(ServerError)
        }
    }

    fn delete_document(&mut self, token: &Token, document_id: &DocumentID) -> Result<(), VaultError> {
        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        if self.is_client_owner_of_document(&organization_name, &document_id)? {
            let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
            fs::remove_file(&self.organization_document_key_path(&organization_name, &document_id)).map_err(|_| ServerError)
        } else {
            Err(ServerError)
        }
    }

    fn get_public_key_of_organization(&mut self, organization_name: &str) -> Result<dryocbox::PublicKey, VaultError> {
        let organization_name = validate_and_standardize_name(organization_name)?;
        load(&self.organization_public_key_path(&organization_name))
    }

    fn add_owner(&mut self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey)
                 -> Result<(), VaultError> {
        let other_organization_name = validate_and_standardize_name(other_organization_name)?;

        let organization_name = self.sessions.get_organization_name_from_token(&token).ok_or(ServerError)?;
        if self.is_client_owner_of_document(&organization_name, &document_id)? {
            save(&encrypted_document_key, &self.organization_document_key_path(&other_organization_name, &document_id), false)
        } else {
            Err(ServerError)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use dryoc::{dryocbox, pwhash};
    use uuid::Uuid;
    use crate::data::{DocumentID, EncryptedDocument, random_encrypted_document_key, Token, UserShare};
    use crate::error::VaultError;
    use crate::server::local_server::LocalServer;
    use crate::server_connection::ServerConnection;

    fn create_server() -> LocalServer {
        LocalServer::new(
            &PathBuf::from("test data server").join(Uuid::new_v4().to_string())
        )
    }

    fn create_server_with_organizations_and_documents() -> (LocalServer, Vec<Token>, DocumentID) {
        let mut server = create_server();

        let mut tokens = Vec::new();
        tokens.push(create_organization_and_unlock("ApertureScience", &mut server));
        tokens.push(create_organization_and_unlock("BlackMesa", &mut server));

        server.new_document(&tokens[0], &EncryptedDocument::create_random(), &random_encrypted_document_key()).unwrap();
        let document_id = server.list_documents(&tokens[0]).unwrap().iter().next().unwrap().0.clone();

        (server, tokens, document_id)
    }

    fn create_organization_and_unlock(name: &str, server: &mut LocalServer) -> Token {
        let key_pair = create_organization(name, "user1", "user2", server).unwrap();

        let (.., encrypted_token) =
            server.unlock_vault(name, "user1", "user2").unwrap();

        encrypted_token.unseal_to_vec(&key_pair).unwrap()
    }

    fn create_organization(name: &str, username1: &str, username2: &str, server: &mut LocalServer) -> Result<dryocbox::KeyPair, VaultError> {
        let key_pair = dryocbox::KeyPair::gen();

        let mut user_data = HashMap::new();
        user_data.insert(username1.to_string(), UserShare::create_random());
        user_data.insert(username2.to_string(), UserShare::create_random());

        server.create_organization(
            name,
            &user_data,
            &key_pair.public_key,
            &pwhash::Config::default(),
        )?;

        Ok(key_pair)
    }


    #[test]
    fn correct_token() {
        let (mut server, tokens, document_id) = create_server_with_organizations_and_documents();

        server.get_document(&tokens[0], &document_id).unwrap();
        server.update_document(&tokens[0], &document_id, &EncryptedDocument::create_random()).unwrap();
        server.add_owner(&tokens[0], &document_id, "BlackMesa", &random_encrypted_document_key()).unwrap();
        server.delete_document(&tokens[0], &document_id).unwrap();
    }

    #[test]
    fn wrong_token() {
        let (mut server, tokens, document_id) = create_server_with_organizations_and_documents();

        assert!(server.get_document(&tokens[1], &document_id).is_err());
        assert!(server.update_document(&tokens[1], &document_id, &EncryptedDocument::create_random()).is_err());
        assert!(server.add_owner(&tokens[1], &document_id, "BlackMesa", &random_encrypted_document_key()).is_err());
        assert!(server.delete_document(&tokens[1], &document_id).is_err());
    }

    #[test]
    fn names_validation_create_organization() {
        let mut server = create_server();

        assert!(matches!(
            create_organization("../../name", "user1", "user2", &mut server),
            Err(VaultError::ValidationError)
        ));

        assert!(matches!(
            create_organization("name", "../../user1", "user2", &mut server),
            Err(VaultError::ValidationError)
        ));
    }

    #[test]
    fn names_validation_unlock_vault() {
        let mut server = create_server();

        assert!(matches!(
            server.unlock_vault("../../name", "user1", "user2"),
            Err(VaultError::ValidationError)
        ));

        assert!(matches!(
            server.unlock_vault("name", "../../user1", "user2"),
            Err(VaultError::ValidationError)
        ));
    }

    #[test]
    fn names_validation_revoke_user() {
        let (mut server, tokens, ..) = create_server_with_organizations_and_documents();

        assert!(matches!(
            server.revoke_user(&tokens[0], "../../user1"),
            Err(VaultError::ValidationError)
        ));
    }

    #[test]
    fn names_validation_get_organization_key() {
        let (mut server, ..) = create_server_with_organizations_and_documents();

        assert!(matches!(
            server.get_public_key_of_organization("../../org"),
            Err(VaultError::ValidationError)
        ));
    }
}