use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::net::IpAddr::V4;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, routing::post};
use axum::extract::State;
use axum_server::tls_rustls::RustlsConfig;
use dryoc::{dryocbox, pwhash};
use reqwest::StatusCode;
use rustls::{Certificate, PrivateKey, ServerConfig};
use crate::config::{CLIENT_CERTIFICATE_KEY_LOCATION, CLIENT_CERTIFICATE_LOCATION};

use crate::data::{DocumentID, EncryptedDocument, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::server::local_server::LocalServer;
use crate::server_connection::ServerConnection;
use crate::utils;

pub const CREATE_ORGANIZATION_ENDPOINT: &str = "/create_organization";
pub const UNLOCK_VAULT_ENDPOINT: &str = "/unlock_vault";
pub const REVOKE_USER_ENDPOINT: &str = "/revoke_user";
pub const REVOKE_TOKEN_ENDPOINT: &str = "/revoke_token";
pub const NEW_DOCUMENT_ENDPOINT: &str = "/new_document";
pub const LIST_DOCUMENTS_ENDPOINT: &str = "/list_documents";
pub const GET_DOCUMENT_KEY_ENDPOINT: &str = "/get_document_key";
pub const GET_DOCUMENT_ENDPOINT: &str = "/get_document";
pub const UPDATE_DOCUMENT_ENDPOINT: &str = "/update_document";
pub const DELETE_DOCUMENT_ENDPOINT: &str = "/delete_document";
pub const GET_PUBLIC_KEY_ENDPOINT: &str = "/get_public_key_of_organization";
pub const ADD_OWNER_ENDPOINT: &str = "/add_owner";

#[tokio::main]
pub async fn run_http_server(port: u16, data_storage_directory: PathBuf) {
    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![Certificate(utils::get_certificate_der_from_pem_file(&CLIENT_CERTIFICATE_LOCATION.into()))],
            PrivateKey(utils::get_key_der_from_pem_file(&CLIENT_CERTIFICATE_KEY_LOCATION.into())),
        ).unwrap();

    let server_state = Arc::new(Mutex::new(
        LocalServer::new(&PathBuf::from(data_storage_directory))
    ));

    let app = Router::new()
        .route(CREATE_ORGANIZATION_ENDPOINT, post(create_organization_handler))
        .route(UNLOCK_VAULT_ENDPOINT, post(unlock_vault_handler))
        .route(REVOKE_USER_ENDPOINT, post(revoke_user_handler))
        .route(REVOKE_TOKEN_ENDPOINT, post(revoke_token_handler))
        .route(NEW_DOCUMENT_ENDPOINT, post(new_document_handler))
        .route(LIST_DOCUMENTS_ENDPOINT, post(list_documents_handler))
        .route(GET_DOCUMENT_KEY_ENDPOINT, post(get_document_key_handler))
        .route(GET_DOCUMENT_ENDPOINT, post(get_document_handler))
        .route(UPDATE_DOCUMENT_ENDPOINT, post(update_document_handler))
        .route(DELETE_DOCUMENT_ENDPOINT, post(delete_document_handler))
        .route(GET_PUBLIC_KEY_ENDPOINT, post(get_public_key_handler))
        .route(ADD_OWNER_ENDPOINT, post(add_owner_handler))
        .with_state(server_state);


    axum_server::bind_rustls(
        SocketAddr::new(V4(Ipv4Addr::new(0, 0, 0, 0)), port),
        RustlsConfig::from_config(Arc::new(config)))
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn create_organization_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((organization_name, users_data, public_key, argon2_config)): Json<(String, HashMap<String, UserShare>, dryocbox::PublicKey, pwhash::Config)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .create_organization(&organization_name, &users_data, &public_key, &argon2_config)
    )
}

async fn unlock_vault_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((organization_name, user_name1, user_name2)): Json<(String, String, String)>,
)
    -> Result<Json<(UserShare, UserShare, pwhash::Config, dryocbox::PublicKey, EncryptedToken)>, StatusCode> {
    json_handler_result(
        local_server.lock().unwrap()
            .unlock_vault(&organization_name, &user_name1, &user_name2)
    )
}

async fn revoke_user_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, user_name)): Json<(Token, String)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .revoke_user(&token, &user_name)
    )
}

async fn revoke_token_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json(token): Json<Token>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .revoke_token(&token)
    )
}

async fn new_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, encrypted_document, encrypted_key)): Json<(Token, EncryptedDocument, EncryptedDocumentKey)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .new_document(&token, &encrypted_document, &encrypted_key)
    )
}

async fn list_documents_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json(token): Json<Token>,
)
    -> Result<Json<HashMap<DocumentID, EncryptedDocumentNameAndKey>>, StatusCode> {
    json_handler_result(
        local_server.lock().unwrap()
            .list_documents(&token)
    )
}

async fn get_document_key_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<Json<EncryptedDocumentKey>, StatusCode> {
    json_handler_result(
        local_server.lock().unwrap()
            .get_document_key(&token, &document_id)
    )
}

async fn get_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<Json<EncryptedDocument>, StatusCode> {
    json_handler_result(
        local_server.lock().unwrap()
            .get_document(&token, &document_id)
    )
}

async fn update_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id, encrypted_document)): Json<(Token, DocumentID, EncryptedDocument)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .update_document(&token, &document_id, &encrypted_document)
    )
}

async fn delete_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .delete_document(&token, &document_id)
    )
}

async fn get_public_key_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json(organization_name): Json<String>,
)
    -> Result<Json<dryocbox::PublicKey>, StatusCode> {
    json_handler_result(
        local_server.lock().unwrap()
            .get_public_key_of_organization(&organization_name)
    )
}

async fn add_owner_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id, other_organization_name, encrypted_document_key)): Json<(Token, DocumentID, String, EncryptedDocumentKey)>,
)
    -> Result<(), StatusCode> {
    convert_option_to_handler_result(
        local_server.lock().unwrap()
            .add_owner(&token, &document_id, &other_organization_name, &encrypted_document_key)
    )
}

fn convert_option_to_handler_result<A>(option: Option<A>) -> Result<A, StatusCode> {
    option.ok_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn json_handler_result<A>(option: Option<A>) -> Result<Json<A>, StatusCode> {
    Ok(
        Json(
            convert_option_to_handler_result(option)?
        )
    )
}