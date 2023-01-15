#[cfg(test)]
use std::path::Path;
use std::thread;

use dryoc::pwhash;
use rand::{Rng, thread_rng};
use uuid::Uuid;

use vault::client::http_connection::HttpConnection;
use vault::client::organization_creation::{OrganizationBuilder};
use vault::client::session_controller::Controller;
use vault::data::Document;
use vault::error::VaultError;
use vault::server::http_server::run_http_server;
use vault::server_connection::ServerConnection;
use vault::error::VaultError::{ServerError, DocumentNotFound};

const TEST_DATA_DIRECTORY_PATH: &str = "./test data http";


const FIRST_ALLOWED_TCP_PORT: u16 = 1024;
const LAST_TCP_PORT: u16 = 65534;

fn fast_and_unsafe_argon_config() -> pwhash::Config {
    pwhash::Config::default().with_memlimit(10000).with_opslimit(1)
}

fn set_up_server_with_organizations() -> HttpConnection {
    // As multiple tests are run in parallel,
    // we use a random port and a random data folder to avoid collisions
    let server_vault_data_directory = Path::new(TEST_DATA_DIRECTORY_PATH).join(Uuid::new_v4().to_string());
    let server_port = thread_rng().gen_range(FIRST_ALLOWED_TCP_PORT..LAST_TCP_PORT);
    thread::spawn(move || run_http_server(server_port, server_vault_data_directory));


    let mut server = HttpConnection::new(server_port);

    OrganizationBuilder::new("ApertureScience", &fast_and_unsafe_argon_config())
        .unwrap()
        .add_user("Glados", "glados80m32Z$GIdKGK*M").unwrap()
        .add_user("Chell", "chell80m32Z$GIdKGK*M").unwrap()
        .add_user("Wheatley", "wheatley80m32Z$GIdKGK*M").unwrap()
        .add_user("Cave", "cave80m32Z$GIdKGK*M").unwrap()
        .create_organization(&mut server).unwrap();


    OrganizationBuilder::new("StarWars", &fast_and_unsafe_argon_config())
        .unwrap()
        .add_user("DarthVador", "darthvador80m32Z$GIdKGK*M").unwrap()
        .add_user("Luke", "luke80m32Z$GIdKGK*M").unwrap()
        .add_user("Leila", "leila80m32Z$GIdKGK*M").unwrap()
        .add_user("R2D2", "r2d280m32Z$GIdKGK*M").unwrap()
        .create_organization(&mut server).unwrap();


    OrganizationBuilder::new("LotR", &fast_and_unsafe_argon_config())
        .unwrap()
        .add_user("Gandalf", "gandalf80m32Z$GIdKGK*M").unwrap()
        .add_user("Frodo", "frodo80m32Z$GIdKGK*M").unwrap()
        .create_organization(&mut server).unwrap();

    server
}

fn authenticate_clients_for_server<A: ServerConnection + Clone>(server: &mut A) -> Vec<Controller<A>> {
    vec![
        ("ApertureScience", "Chell", "chell80m32Z$GIdKGK*M", "Cave", "cave80m32Z$GIdKGK*M"),
        ("StarWars", "Luke", "luke80m32Z$GIdKGK*M", "Leila", "leila80m32Z$GIdKGK*M"),
        ("LotR", "Gandalf", "gandalf80m32Z$GIdKGK*M", "Frodo", "frodo80m32Z$GIdKGK*M"),
    ]
        .iter()
        .map(|(organization, user1, password1, user2, password2)|
            Controller::unlock_vault_for_organization(
                server,
                organization,
                user1, password1,
                user2, password2)
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
    client_controllers[0].upload(&document).unwrap();

    let document = Document {
        name: "aperture science 2".to_string(),
        content: "aperture science content 2".to_string(),
    };
    client_controllers[0].upload(&document).unwrap();

    let document = Document {
        name: "aperture science star wars shared".to_string(),
        content: "shared content".to_string(),
    };
    client_controllers[0].upload(&document).unwrap();
    client_controllers[0].share("aperture science star wars shared", "StarWars").unwrap();

    let document = Document {
        name: "star wars".to_string(),
        content: "star wars content".to_string(),
    };
    client_controllers[1].upload(&document).unwrap();

    client_controllers
}

#[test]
fn create_organization_weak_password() {
    let builder = OrganizationBuilder::new("ApertureScience", &fast_and_unsafe_argon_config()).unwrap();

    assert!(
        matches!(
            builder.clone().add_user("username", "1234"),
            Err(VaultError::PasswordNotStrong(_))
        ),
        "Weak password"
    );

    assert!(
        matches!(
            builder.clone().add_user("username", "ApertureScience&42"),
            Err(VaultError::PasswordNotStrong(_))
        ),
        "Strong password but similar to organization name"
    );

    assert!(
        matches!(
            builder.clone().add_user("usernameFooBarJohnPeter", "usernameFooBarJohnPeter1234"),
            Err(VaultError::PasswordNotStrong(_))
        ),
        "Strong password but similar to user name"
    );
}

#[test]
fn already_existing_organization_name() {
    let mut server = set_up_server_with_organizations();

    let result = OrganizationBuilder::new("ApertureScience", &fast_and_unsafe_argon_config())
        .unwrap()
        .add_user("user1", "80m32Z$GIdKGK*M").unwrap()
        .add_user("user2", "80m32Z$GIdKGK*M").unwrap()
        .create_organization(&mut server);


    assert!(matches!(result, Err(ServerError)));
}

#[test]
fn create_organizations_and_unlock() {
    let mut server = set_up_server_with_organizations();
    authenticate_clients_for_server(&mut server);
}

#[test]
fn delete_user() {
    let mut server = set_up_server_with_organizations();
    let mut client_controller =
        Controller::unlock_vault_for_organization(
            &mut server,
            "StarWars",
            "Luke", "luke80m32Z$GIdKGK*M",
            "Leila", "leila80m32Z$GIdKGK*M",
        ).unwrap();

    client_controller.revoke_user("DarthVador").unwrap();

    let controller_result = Controller::unlock_vault_for_organization(
        &mut server,
        "StarWars",
        "DarthVador", "darthvador80m32Z$GIdKGK*M",
        "Leila", "leila80m32Z$GIdKGK*M",
    );
    assert!(matches!(controller_result, Err(ServerError)));
}

#[test]
fn delete_user_wrong_token() {
    let mut server = set_up_server_with_organizations();
    let mut client_controllers = authenticate_clients_for_server(&mut server);

    assert!(matches!(client_controllers[0].revoke_user("DarthVador"), Err(ServerError)));

    Controller::unlock_vault_for_organization(
        &mut server,
        "StarWars",
        "Luke", "luke80m32Z$GIdKGK*M",
        "Leila", "leila80m32Z$GIdKGK*M",
    ).unwrap();
}

#[test]
fn revoke_token() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    client_controllers[0].revoke_token().unwrap();

    assert!(matches!(client_controllers[0].list_document_names(), Err(ServerError)));
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

    assert!(matches!(client_controllers[0].download("aperture science 1"), Err(DocumentNotFound)));

    let downloaded_document = client_controllers[0].download("new name").unwrap();
    assert_eq!(new_document, downloaded_document);
}

#[test]
fn update_shared_document() {
    let mut client_controllers = set_up_server_with_organizations_and_documents();

    let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
    client_controllers[0].update("aperture science star wars shared", &new_document).unwrap();

    assert!(matches!(client_controllers[1].download("aperture science star wars shared"), Err(DocumentNotFound)));

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