#[cfg(test)]
use std::collections::HashMap;
use std::path::Path;
use std::thread;

use dryoc::pwhash;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

use vault::client::controller;
use vault::client::controller::Controller;
use vault::client::http_connection::HttpConnection;
use vault::data::Document;
use vault::server::http_server::run_http_server;
use vault::server_connection::ServerConnection;

const TEST_DATA_DIRECTORY_PATH: &str = "./test data http";

fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}


const FIRST_ALLOWED_TCP_PORT: u16 = 1024;
const LAST_TCP_PORT: u16 = 65534;

fn fast_and_unsafe_argon_config() -> pwhash::Config {
    pwhash::Config::default().with_memlimit(10000).with_opslimit(1)
}

fn set_up_server_with_organizations() -> HttpConnection {
    // As multiple tests are run in parallel,
    // we use a random port and a random data folder to avoid collisions
    let server_vault_data_directory = Path::new(TEST_DATA_DIRECTORY_PATH).join(random_string(30));
    let server_port = thread_rng().gen_range(FIRST_ALLOWED_TCP_PORT..LAST_TCP_PORT);
    thread::spawn(move || run_http_server(server_port, server_vault_data_directory));

    let mut server = HttpConnection::new(server_port);

    let mut as_user_credentials = HashMap::new();
    as_user_credentials.insert("Glados".to_string(), "gladospassword".to_string());
    as_user_credentials.insert("Chell".to_string(), "chellpassword".to_string());
    as_user_credentials.insert("Wheatley".to_string(), "weathleypassword".to_string());
    as_user_credentials.insert("Cave".to_string(), "cavepassword".to_string());

    controller::create_organization(&mut server, "Aperture Science", &as_user_credentials, &fast_and_unsafe_argon_config()).unwrap();


    let mut sw_user_credentials = HashMap::new();
    sw_user_credentials.insert("Darth Vador".to_string(), "darthvadorpassword".to_string());
    sw_user_credentials.insert("Luke".to_string(), "lukepassword".to_string());
    sw_user_credentials.insert("Leila".to_string(), "leilapassword".to_string());
    sw_user_credentials.insert("R2D2".to_string(), "r2d2password".to_string());

    controller::create_organization(&mut server, "Star Wars", &sw_user_credentials, &fast_and_unsafe_argon_config()).unwrap();


    let mut lotr_user_credentials = HashMap::new();
    lotr_user_credentials.insert("Gandalf".to_string(), "gandalfpassword".to_string());
    lotr_user_credentials.insert("Frodo".to_string(), "frodopassword".to_string());

    controller::create_organization(&mut server, "LotR", &lotr_user_credentials, &fast_and_unsafe_argon_config()).unwrap();

    server
}

fn authenticate_clients_for_server<A: ServerConnection + Clone>(server: &mut A) -> Vec<Controller<A>> {
    vec![
        ("Aperture Science", "Chell", "chellpassword", "Cave", "cavepassword"),
        ("Star Wars", "Luke", "lukepassword", "Leila", "leilapassword"),
        ("LotR", "Gandalf", "gandalfpassword", "Frodo", "frodopassword"),
    ]
        .iter()
        .map(|(organization, user1, password1, user2, password2)|
            Controller::unlock_vault_for_organization(
                server,
                organization,
                user1, password1,
                user2, password2,
                &fast_and_unsafe_argon_config())
                .unwrap())
        .collect()
}

fn set_up_server_with_organizations_and_documents() -> Vec<Controller<HttpConnection>> {
    let mut server = set_up_server_with_organizations();
    let mut client_controllers = authenticate_clients_for_server(&mut server);

    let document = Document {
        name: "aperture science 1".to_string(),
        content: "aperture science content 1".to_string(),
    };
    client_controllers[0].upload(&document);

    let document = Document {
        name: "aperture science 2".to_string(),
        content: "aperture science content 2".to_string(),
    };
    client_controllers[0].upload(&document);

    let document = Document {
        name: "aperture science star wars shared".to_string(),
        content: "shared content".to_string(),
    };
    client_controllers[0].upload(&document);
    client_controllers[0].share("aperture science star wars shared", "Star Wars");

    let document = Document {
        name: "star wars".to_string(),
        content: "star wars content".to_string(),
    };
    client_controllers[1].upload(&document);

    client_controllers
}

#[test]
fn unlock_vault() {
    let mut server = set_up_server_with_organizations();
    authenticate_clients_for_server(&mut server);
}

#[test]
fn delete_user() {
    let mut server = set_up_server_with_organizations();
    let mut client_controller =
        Controller::unlock_vault_for_organization(
            &mut server,
            "Star Wars",
            "Luke", "lukepassword",
            "Leila", "leilapassword",
            &fast_and_unsafe_argon_config(),
        ).unwrap();

    client_controller.revoke_user("Darth Vador").unwrap();

    let controller_option = Controller::unlock_vault_for_organization(
        &mut server,
        "Star Wars",
        "Darth Vador", "darthvadorpassword",
        "Leila", "leilapassword",
        &fast_and_unsafe_argon_config(),
    );
    assert!(controller_option.is_none());
}

#[test]
fn delete_user_wrong_token() {
    let mut server = set_up_server_with_organizations();
    let mut client_controllers = authenticate_clients_for_server(&mut server);

    assert!(client_controllers[0].revoke_user("Darth Vador").is_none());

    Controller::unlock_vault_for_organization(
        &mut server,
        "Star Wars",
        "Luke", "lukepassword",
        "Leila", "leilapassword",
        &fast_and_unsafe_argon_config(),
    ).unwrap();
}

#[test]
fn revoke_token() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    client_controllers[0].revoke_token().unwrap();

    assert!(client_controllers[0].list_document_names().is_none());
    client_controllers[1].list_document_names().unwrap();
}

#[test]
fn list_documents() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    let organization0_document_names = client_controllers[0].list_document_names().unwrap();
    assert_eq!(3, organization0_document_names.len());
    assert!(organization0_document_names.contains(&"aperture science 1".into()));
    assert!(organization0_document_names.contains(&"aperture science 2".into()));
    assert!(organization0_document_names.contains(&"aperture science star wars shared".into()));

    let organization1_document_names = client_controllers[1].list_document_names().unwrap();
    assert_eq!(2, organization1_document_names.len());
    assert!(organization1_document_names.contains(&"star wars".into()));
    assert!(organization1_document_names.contains(&"aperture science star wars shared".into()));

    let organization2_document_names = client_controllers[2].list_document_names().unwrap();
    assert_eq!(0, organization2_document_names.len());
}

#[test]
fn get_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    let document1 = client_controllers[0].download("aperture science 1").unwrap();
    assert_eq!(document1, Document { name: "aperture science 1".to_string(), content: "aperture science content 1".to_string() });

    let document2 = client_controllers[0].download("aperture science 2").unwrap();
    assert_eq!(document2, Document { name: "aperture science 2".to_string(), content: "aperture science content 2".to_string() });

    let document3 = client_controllers[0].download("aperture science star wars shared").unwrap();
    assert_eq!(document3, Document { name: "aperture science star wars shared".to_string(), content: "shared content".to_string() });

    let document4 = client_controllers[1].download("aperture science star wars shared").unwrap();
    assert_eq!(document4, Document { name: "aperture science star wars shared".to_string(), content: "shared content".to_string() });

    let document5 = client_controllers[1].download("star wars").unwrap();
    assert_eq!(document5, Document { name: "star wars".to_string(), content: "star wars content".to_string() });
}

#[test]
fn update_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
    client_controllers[0].update("aperture science 1", &new_document).unwrap();

    assert!(client_controllers[0].download("aperture science 1").is_none());

    let downloaded_document = client_controllers[0].download("new name").unwrap();
    assert_eq!(new_document, downloaded_document);
}

#[test]
fn update_shared_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
    client_controllers[0].update("aperture science star wars shared", &new_document).unwrap();

    assert!(client_controllers[1].download("aperture science star wars shared").is_none());

    let downloaded_document = client_controllers[1].download("new name").unwrap();
    assert_eq!(new_document, downloaded_document);
}

#[test]
fn delete_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    client_controllers[0].delete("aperture science 1").unwrap();

    let organization_document_names = client_controllers[0].list_document_names().unwrap();
    assert!(!organization_document_names.contains(&"aperture science 1".into()));
}

#[test]
fn delete_shared_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    client_controllers[0].delete("aperture science star wars shared").unwrap();

    let organization_document_names = client_controllers[1].list_document_names().unwrap();
    assert!(organization_document_names.contains(&"aperture science star wars shared".into()));
}