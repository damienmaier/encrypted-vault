fn new_document(name: &str, content: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    unimplemented!()
}

fn get_document_name(encrypted_name: Vec<u8>, encrypted_document_key: Vec<u8>) -> String {
    unimplemented!()
}

fn get_document(encrypted_name: Vec<u8>,
                encrypted_content: Vec<u8>,
                encrypted_document_key: Vec<u8>)
    -> (String, String) {
    unimplemented!()
}

fn update_document(name: &str, content: &str, encrypted_document_key: Vec<u8>)
    -> (Vec<u8>, Vec<u8>) {
    unimplemented!()
}

fn add_owner(encrypted_document_key: Vec<u8>,
             other_organization_public_key: dryoc::dryocbox::PublicKey)
    -> Vec<u8> {
    unimplemented!()
}