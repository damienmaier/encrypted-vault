use crate::symmetric_encryption_helper::SymEncryptedData;

#[derive(PartialEq, Debug)]
pub(crate) struct Document {
    pub(crate) name: Vec<u8>,
    pub(crate) content: Vec<u8>,
}

impl Document {
    pub(crate) fn encrypt(&self, key: &dryoc::dryocsecretbox::Key) -> EncryptedDocument {
        EncryptedDocument {
            name: SymEncryptedData::encrypt(&self.name, &key),
            content: SymEncryptedData::encrypt(&self.content, &key),
        }
    }
}

pub(crate) struct EncryptedDocument {
    pub(crate) name: SymEncryptedData,
    pub(crate) content: SymEncryptedData,
}

impl EncryptedDocument {
    pub(crate) fn decrypt(&self, key: &dryoc::dryocsecretbox::Key) -> Document {
        Document {
            name: self.name.decrypt(key),
            content: self.content.decrypt(key),
        }
    }
}