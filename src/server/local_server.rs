use std::collections::HashMap;
use std::fs;
use std::fs::DirEntry;
use std::path::PathBuf;

use data_encoding::BASE32;
use dryoc::{dryocbox, pwhash, rng};
use dryoc::dryocbox::DryocBox;

use crate::data::{DOCUMENT_ID_LENGTH_BYTES, DocumentID, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::data::EncryptedDocument;
use crate::server::serde_json_disk::{load, save};
use crate::server::session_manager::SessionManager;
use crate::server_connection::ServerConnection;


pub struct LocalServer {
    data_path: PathBuf,
    sessions: SessionManager
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

    fn organization_users_directory(&self, organization_name: &str, username: &str) -> PathBuf {
        self.organization_directory(organization_name).join(USERS_FOLDER_NAME).join(username)
    }

    fn organization_document_keys_directory(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(DOCUMENTS_KEYS_FOLDER_NAME)
    }

    fn organization_document_key_path(&self, organization_name: &str, document_id: &DocumentID) -> PathBuf {
        self.organization_document_keys_directory(organization_name).join(document_id)
    }

    fn document_path(&self, document_id: &DocumentID) -> PathBuf {
        self.data_path.as_path().join(DOCUMENTS_FOLDER_NAME).join(document_id)
    }


    fn is_client_owner_of_document(&mut self, token: &Token, document_id: &DocumentID) -> Option<bool> {
        let organization_name = self.sessions.get_organization_name_from_token(&token)?;

        Some(
            fs::read_dir(self.organization_document_keys_directory(&organization_name)).ok()?
                .any(|x| x.unwrap().file_name().to_str().unwrap() == document_id)
        )
    }
}

impl ServerConnection for LocalServer {
    fn create_organization(&mut self,
                           organization_name: &str,
                           users_data: &HashMap<String, UserShare>,
                           public_key: &dryocbox::PublicKey,
                           argon2_config: &pwhash::Config
    )
                           -> Option<()>
    {
        save(public_key, &self.organization_public_key_path(organization_name), false)?;
        save(argon2_config, &self.organization_argon_config_path(organization_name), false)?;
        for (user_name, user_share) in users_data {
            save(user_share, &self.organization_users_directory(organization_name, user_name), false)?;
        }
        fs::create_dir_all(self.organization_document_keys_directory(organization_name)).ok()?;
        Some(())
    }

    fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                    -> Option<(UserShare, UserShare, pwhash::Config, dryocbox::PublicKey, EncryptedToken)> {
        let public_key: dryocbox::PublicKey = load(&self.organization_public_key_path(organization_name))?;
        let argon_config: pwhash::Config = load(&self.organization_argon_config_path(organization_name))?;

        let user_share1: UserShare = load(&self.organization_users_directory(organization_name, user_name1))?;
        let user_share2: UserShare = load(&self.organization_users_directory(organization_name, user_name2))?;

        let token = self.sessions.new_session(organization_name);
        let encrypted_token = DryocBox::seal_to_vecbox(&token, &public_key).ok()?;

        Some((user_share1, user_share2, argon_config, public_key, encrypted_token))
    }

    fn revoke_user(&mut self, token: &Token, user_name: &str) -> Option<()> {
        let organization_name = self.sessions.get_organization_name_from_token(&token)?;
        fs::remove_file(&self.organization_users_directory(&organization_name, user_name)).ok()
    }

    fn revoke_token(&mut self, token: &Token) -> Option<()> {
        self.sessions.end_session(token);
        Some(())
    }

    fn new_document(&mut self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &EncryptedDocumentKey)
                    -> Option<()> {
        let organization_name = self.sessions.get_organization_name_from_token(&token)?;
        let document_id = BASE32.encode(&rng::randombytes_buf(DOCUMENT_ID_LENGTH_BYTES));

        save(encrypted_document, &self.document_path(&document_id), false)?;
        save(encrypted_key, &self.organization_document_key_path(&organization_name, &document_id), false)?;

        Some(())
    }

    fn list_documents(&mut self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDocumentNameAndKey>> {
        let organization_name = self.sessions.get_organization_name_from_token(&token)?;

        let build_data = |dir_entry: DirEntry| -> (DocumentID, EncryptedDocumentNameAndKey) {
            let document_id_os_str = dir_entry.file_name();
            let document_id = document_id_os_str.to_str().unwrap().to_string();
            let encrypted_document: EncryptedDocument = load(&self.document_path(&document_id)).unwrap();
            let encrypted_key = load(&self.organization_document_key_path(&organization_name, &document_id)).unwrap();

            (document_id, EncryptedDocumentNameAndKey { data: encrypted_document.name, key: encrypted_key })
        };

        let documents_list: HashMap<DocumentID, EncryptedDocumentNameAndKey> =
            fs::read_dir(self.organization_document_keys_directory(&organization_name)).ok()?
                .map(|x| x.unwrap())
                .filter(|dir_entry| dir_entry.file_type().unwrap().is_file())
                .map(build_data)
                .collect();

        Some(documents_list)
    }

    fn get_document_key(&mut self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocumentKey> {
        let organization_name = self.sessions.get_organization_name_from_token(&token)?;
        load(&self.organization_document_key_path(&organization_name, &document_id))
    }

    fn get_document(&mut self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            load(&self.document_path(&document_id))
        } else {
            None
        }
    }

    fn update_document(&mut self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                       -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            save(encrypted_document, &self.document_path(&document_id), true)
        } else {
            None
        }
    }

    fn delete_document(&mut self, token: &Token, document_id: &DocumentID) -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            let organization_name = self.sessions.get_organization_name_from_token(&token)?;
            fs::remove_file(&self.organization_document_key_path(&organization_name, &document_id)).ok()
        } else {
            None
        }
    }

    fn get_public_key_of_organization(&mut self, organization_name: &str) -> Option<dryocbox::PublicKey> {
        load(&self.organization_public_key_path(organization_name))
    }

    fn add_owner(&mut self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &EncryptedDocumentKey)
                 -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            save(&encrypted_document_key, &self.organization_document_key_path(other_organization_name, &document_id), false)
        } else {
            None
        }
    }
}