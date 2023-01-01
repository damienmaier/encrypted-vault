use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use dryoc::{dryocbox, rng};
use dryoc::dryocbox::DryocBox;

use crate::data::{DocumentID, EncryptedDataEncryptedKey, Organization, Token, TOKEN_LENGTH_BYTES, UserShare};
use crate::EncryptedDocument;
use crate::serde_json_disk::{load, save};

pub(crate) struct Server {
    data_path: PathBuf,
    tokens: HashMap<Token, String>,
}

const ORGANIZATIONS_FOLDER_NAME: &str = "organizations";
const PUBLIC_KEY_FILE_NAME: &str = "public_key";
const USERS_DIRECTORY_NAME: &str = "users";

impl Server {
    pub fn new(data_path: &PathBuf) -> Server {
        Server { data_path: data_path.clone(), tokens: HashMap::new() }
    }

    fn organization_directory(&self, organization_name: &str) -> PathBuf {
        self.data_path.as_path().join(ORGANIZATIONS_FOLDER_NAME).join(organization_name)
    }

    fn organization_users_directory(&self, organization_name: &str) -> PathBuf {
        self.data_path.as_path().join(ORGANIZATIONS_FOLDER_NAME).join(organization_name).join(USERS_DIRECTORY_NAME)
    }

    pub fn create_organization(&self, organization_name: &str, users_data: &HashMap<String, UserShare>, public_key: &dryocbox::PublicKey)
                               -> Option<()>
    {
        let organization = Organization { public_key: public_key.clone(), users_data: users_data.clone() };
        save(&organization.public_key,&self.organization_directory(organization_name).join(PUBLIC_KEY_FILE_NAME));
        for (user_name, user_share) in users_data{
            save(user_share, &self.organization_users_directory(organization_name).join(user_name));
        }
        Some(())
    }

    pub fn unlock_vault(&mut self, organization_name: &str, user_name1: &str, user_name2: &str)
                        -> Option<(UserShare, UserShare, dryocbox::PublicKey, dryocbox::VecBox)> {
        let public_key: dryocbox::PublicKey = load(&self.organization_directory(organization_name).join(PUBLIC_KEY_FILE_NAME))?;

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
        unimplemented!()
    }

    pub fn list_documents(&self, token: &Token) -> Option<HashMap<DocumentID, EncryptedDataEncryptedKey>> {
        unimplemented!()
    }

    pub fn get_document_key(&self, token: &Token, document_id: &DocumentID) -> Option<dryocbox::VecBox> {
        unimplemented!()
    }

    pub fn download_document(&self, token: &Token, document_id: &DocumentID) -> Option<EncryptedDocument> {
        unimplemented!()
    }

    pub fn update_document(&self, token: &Token, document_id: &DocumentID, encrypted_document: &EncryptedDocument)
                           -> Option<()> {
        unimplemented!()
    }

    pub fn delete_document(&self, token: &Token, document_id: &DocumentID) -> Option<()> {
        unimplemented!()
    }

    pub fn get_public_key_of_organization(&self, organization_name: &str) -> Option<dryocbox::PublicKey> {
        unimplemented!()
    }

    pub fn add_owner(&self, token: &Token, document_id: &DocumentID, other_organization_name: &str, encrypted_document_key: &dryocbox::VecBox)
                     -> Option<()> {
        unimplemented!()
    }
}