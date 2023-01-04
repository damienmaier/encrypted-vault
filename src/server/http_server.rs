use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::net::IpAddr::V4;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use axum::{routing::post, Router, Json};
use axum::extract::{State};
use dryoc::dryocbox;
use reqwest::StatusCode;
use crate::config::{ADD_OWNER_ENDPOINT, CREATE_ORGANIZATION_ENDPOINT, DELETE_DOCUMENT_ENDPOINT, GET_DOCUMENT_ENDPOINT, GET_DOCUMENT_KEY_ENDPOINT, GET_PUBLIC_KEY_ENDPOINT, LIST_DOCUMENTS_ENDPOINT, NEW_DOCUMENT_ENDPOINT, REVOKE_USER_ENDPOINT, UNLOCK_VAULT_ENDPOINT, UPDATE_DOCUMENT_ENDPOINT};
use crate::data::{DocumentID, EncryptedDocument, EncryptedDocumentKey, EncryptedDocumentNameAndKey, EncryptedToken, Token, UserShare};
use crate::server::local_server::LocalServer;
use crate::server_connection::ServerConnection;

#[tokio::main]
pub async fn run_http_server(port: u16, data_storage_directory: PathBuf) {
    let server_state = Arc::new(Mutex::new(
        LocalServer::new(&PathBuf::from(data_storage_directory))
    ));

    let app = Router::new()
        .route(CREATE_ORGANIZATION_ENDPOINT, post(create_organization_handler))
        .route(UNLOCK_VAULT_ENDPOINT, post(unlock_vault_handler))
        .route(REVOKE_USER_ENDPOINT, post(revoke_user_handler))
        .route(NEW_DOCUMENT_ENDPOINT, post(new_document_handler))
        .route(LIST_DOCUMENTS_ENDPOINT, post(list_documents_handler))
        .route(GET_DOCUMENT_KEY_ENDPOINT, post(get_document_key_handler))
        .route(GET_DOCUMENT_ENDPOINT, post(get_document_handler))
        .route(UPDATE_DOCUMENT_ENDPOINT, post(update_document_handler))
        .route(DELETE_DOCUMENT_ENDPOINT, post(delete_document_handler))
        .route(GET_PUBLIC_KEY_ENDPOINT, post(get_public_key_handler))
        .route(ADD_OWNER_ENDPOINT, post(add_owner_handler))
        .with_state(server_state);


    axum::Server::bind(&SocketAddr::new(V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn create_organization_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((organization_name, users_data, public_key)): Json<(String, HashMap<String, UserShare>, dryocbox::PublicKey)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .create_organization(&organization_name, &users_data, &public_key)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}

async fn unlock_vault_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((organization_name, user_name1, user_name2)): Json<(String, String, String)>,
)
    -> Result<Json<(UserShare, UserShare, dryocbox::PublicKey, EncryptedToken)>, StatusCode> {
    Ok(Json(
        local_server.lock().unwrap()
            .unlock_vault(&organization_name, &user_name1, &user_name2)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

async fn revoke_user_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, user_name)): Json<(Token, String)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .revoke_user(&token, &user_name)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}

async fn new_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, encrypted_document, encrypted_key)): Json<(Token, EncryptedDocument, EncryptedDocumentKey)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .new_document(&token, &encrypted_document, &encrypted_key)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}

async fn list_documents_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json(token): Json<Token>,
)
    -> Result<Json<HashMap<DocumentID, EncryptedDocumentNameAndKey>>, StatusCode> {
    Ok(Json(
        local_server.lock().unwrap()
            .list_documents(&token)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

async fn get_document_key_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<Json<EncryptedDocumentKey>, StatusCode> {
    Ok(Json(
        local_server.lock().unwrap()
            .get_document_key(&token, &document_id)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

async fn get_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<Json<EncryptedDocument>, StatusCode> {
    Ok(Json(
        local_server.lock().unwrap()
            .get_document(&token, &document_id)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

async fn update_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id, encrypted_document)): Json<(Token, DocumentID, EncryptedDocument)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .update_document(&token, &document_id, &encrypted_document)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}

async fn delete_document_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id)): Json<(Token, DocumentID)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .delete_document(&token, &document_id)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}

async fn get_public_key_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json(organization_name): Json<String>,
)
    -> Result<Json<dryocbox::PublicKey>, StatusCode> {
    Ok(Json(
        local_server.lock().unwrap()
            .get_public_key_of_organization(&organization_name)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    ))
}

async fn add_owner_handler(
    State(local_server): State<Arc<Mutex<LocalServer>>>,
    Json((token, document_id, other_organization_name, encrypted_document_key)): Json<(Token, DocumentID, String, EncryptedDocumentKey)>,
)
    -> Result<(), StatusCode> {
    Ok(
        local_server.lock().unwrap()
            .add_owner(&token, &document_id, &other_organization_name, &encrypted_document_key)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
    )
}