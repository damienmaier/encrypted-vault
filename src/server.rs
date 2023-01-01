use std::collections::HashMap;
use std::error::Error;
use std::{fs, iter};
use std::fs::{DirEntry, ReadDir};
use std::path::{Path, PathBuf};

use dryoc::{dryocbox, rng};
use dryoc::dryocbox::DryocBox;

use crate::data::{DocumentID, EncryptedDataEncryptedKey, Organization, Token, TOKEN_LENGTH_BYTES, UserShare};
use crate::EncryptedDocument;
use crate::serde_json_disk::{load, save};
use data_encoding::BASE32;


pub(crate) struct Server {
    data_path: PathBuf,
    tokens: HashMap<Token, String>,
}

const ORGANIZATIONS_FOLDER_NAME: &str = "organizations";
const PUBLIC_KEY_FILE_NAME: &str = "public_key";
const USERS_FOLDER_NAME: &str = "users";
const DOCUMENTS_KEYS_FOLDER_NAME: &str = "documents_keys";
const DOCUMENTS_FOLDER_NAME: &str = "documents";

impl Server {
    pub fn new(data_path: &PathBuf) -> Server {
        Server { data_path: data_path.clone(), tokens: HashMap::new() }
    }

    fn organization_directory(&self, organization_name: &str) -> PathBuf {
        self.data_path.as_path().join(ORGANIZATIONS_FOLDER_NAME).join(organization_name)
    }

    fn organization_public_key_path(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(PUBLIC_KEY_FILE_NAME)
    }

    fn organization_users_directory(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(USERS_FOLDER_NAME)
    }

    fn organization_document_keys_directory(&self, organization_name: &str) -> PathBuf {
        self.organization_directory(organization_name).join(DOCUMENTS_KEYS_FOLDER_NAME)
    }

    fn organization_document_key_path(&self, organization_name: &str, document_id: &DocumentID) -> PathBuf {
        self.organization_document_keys_directory(organization_name).join(BASE32.encode(document_id))
    }

    fn documents_directory(&self) -> PathBuf {
        self.data_path.as_path().join(DOCUMENTS_FOLDER_NAME)
    }

    fn document_path(&self, document_id: &DocumentID) -> PathBuf {
        self.documents_directory().join(BASE32.encode(document_id))
    }

    pub fn create_organization(&self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey)
                               -> Option<()>
    {
        let organization = Organization { public_key: public_key.clone(), users_data: users_data.clone() };
        save(&organization.public_key, &self.organization_public_key_path(organization_name));
        for (user_name, user_share) in users_data {
            save(user_share, &self.organization_users_directory(organization_name).join(user_name));
        }
        fs::create_dir_all(self.organization_document_keys_directory(organization_name)).ok()?;
        Some(())
    }

    pub fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                        -> Option<(UserShare, UserShare, dryocbox::PublicKey, dryocbox::VecBox)> {
        let public_key: dryocbox::PublicKey = load(&self.organization_public_key_path(organization_name))?;

        let user_share1: UserShare = load(&self.organization_users_directory(organization_name).join(user_name1))?;
        let user_share2: UserShare = load(&self.organization_users_directory(organization_name).join(user_name2))?;

        let token = rng::randombytes_buf(TOKEN_LENGTH_BYTES);
        self.tokens.insert(token.clone(), organization_name.to_string());
        let encrypted_token = DryocBox::seal_to_vecbox(&token, &public_key).ok()?;

        Some((user_share1, user_share2, public_key, encrypted_token))
    }

    pub fn revoke_user(&self, token: &Token, user_name: &str) -> Option<()> {
        let organization_name = self.tokens.get(token)?;
        fs::remove_file(&self.organization_users_directory(organization_name).join(user_name)).ok()
    }

    pub fn new_document(&self, token: &Token, encrypted_document: &EncryptedDocument, encrypted_key: &dryocbox::VecBox)
                        -> Option<()> {
        let organization_name = self.tokens.get(token)?;
        let document_id = rng::randombytes_buf(TOKEN_LENGTH_BYTES);

        save(encrypted_document, &self.document_path(&document_id))?;
        save(encrypted_key, &self.organization_document_key_path(organization_name, &document_id))?;

        Some(())
    }

    pub fn list_documents(&self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDataEncryptedKey>> {
        let organization_name = self.tokens.get(token)?;

        let build_data = |dir_entry: DirEntry| -> (DocumentID, EncryptedDataEncryptedKey) {
            let document_id_os_str = dir_entry.file_name();
            let document_id = BASE32.decode(document_id_os_str.to_str().unwrap().as_bytes()).unwrap();
            let encrypted_document: EncryptedDocument = load(&self.document_path(&document_id)).unwrap();
            let encrypted_key = load(&self.organization_document_key_path(organization_name, &document_id)).unwrap();

            (document_id, EncryptedDataEncryptedKey { data: encrypted_document.name, key: encrypted_key })
        };

        let documents_list: HashMap<DocumentID, EncryptedDataEncryptedKey> =
            fs::read_dir(self.organization_document_keys_directory(organization_name)).ok()?
                .map(|x| x.unwrap())
                .filter(|dir_entry| dir_entry.file_type().unwrap().is_file())
                .map(build_data)
                .collect();

        Some(documents_list)
    }

    pub fn get_document_key(&self, token: &Token, document_id: &DocumentID) -> Option<dryocbox::VecBox> {
        let organization_name = self.tokens.get(token)?;
        load(&self.organization_document_key_path(organization_name, &document_id))

    }

    pub fn download_document(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            load(&self.document_path(&document_id))
        } else {
            None
        }
    }

    pub fn update_document(&self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                           -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            save(encrypted_document, &self.document_path(&document_id))
        } else {
            None
        }
    }

    pub fn delete_document(&self, token: &Token, document_id: &DocumentID) -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            let organization_name = self.tokens.get(token)?;
            fs::remove_file(&self.organization_document_key_path(organization_name, &document_id)).ok()
        } else {
            None
        }
    }

    pub fn get_public_key_of_organization(&self, organization_name: &str) -> Option<dryocbox::PublicKey> {
        load(&self.organization_public_key_path(organization_name))
    }

    pub fn add_owner(&self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &dryocbox::VecBox)
                     -> Option<()> {
        if self.is_client_owner_of_document(&token, &document_id)? {
            save(&encrypted_document_key, &self.organization_document_key_path(other_organization_name, &document_id))
        } else {
            None
        }
    }

    fn is_client_owner_of_document(&self, token: &Token, document_id: &DocumentID) -> Option<bool> {
        let organization_name = self.tokens.get(token)?;
        let document_id_str = BASE32.encode(document_id);

        Some(
            fs::read_dir(self.organization_document_keys_directory(organization_name)).ok()?
                .any(|x| x.unwrap().file_name().to_str().unwrap() == document_id_str)
        )
    }
}