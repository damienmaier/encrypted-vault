mod client_sever_mock_communication;
mod utils;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::ToSocketAddrs;
    use std::path::{Path, PathBuf};

    use dryoc::dryocbox;
    use dryoc::dryocbox::DryocBox;
    use rand::{Rng, thread_rng};
    use rand::distributions::Alphanumeric;

    use crate::client::AuthenticatedClient;
    use crate::client_unsealing::PrivateKeyProtection;
    use crate::data::{DocumentID, Token};
    use crate::Document;
    use crate::server::Server;
    use crate::tests::client_sever_mock_communication::{create_organization, get_id_of_document_by_name, make_client_get_document_from_server, make_client_get_document_from_server_by_name, make_client_share_document, make_client_update_document_on_server, make_client_upload_document_to_server, unlock_vault_for_organization};
    use crate::tests::utils::random_string;

    const TEST_DATA_DIRECTORY_PATH: &str = "test data";


    fn set_up_server_with_organizations() -> Server {
        // As multiple client_server_tests are run in parallel, use a root folder with a random name to avoid collisions
        let server = Server::new(&Path::new(TEST_DATA_DIRECTORY_PATH).join(random_string(30)));

        let mut as_user_credentials = HashMap::new();
        as_user_credentials.insert("Glados".to_string(), "gladospassword".to_string());
        as_user_credentials.insert("Chell".to_string(), "chellpassword;".to_string());
        as_user_credentials.insert("Wheatley".to_string(), "weathleypassword".to_string());
        as_user_credentials.insert("Cave".to_string(), "cavepassword".to_string());

        create_organization(&server, "Aperture Science", &as_user_credentials);


        let mut sw_user_credentials = HashMap::new();
        sw_user_credentials.insert("Darth Vador".to_string(), "darthvadorpassword".to_string());
        sw_user_credentials.insert("Luke".to_string(), "lukepassword".to_string());
        sw_user_credentials.insert("Leila".to_string(), "leilapassword".to_string());
        sw_user_credentials.insert("R2D2".to_string(), "r2d2password".to_string());

        create_organization(&server, "Star Wars", &sw_user_credentials);


        let mut lotr_user_credentials = HashMap::new();
        lotr_user_credentials.insert("Gandalf".to_string(), "gandalfpassword".to_string());
        lotr_user_credentials.insert("Frodo".to_string(), "frodopassword".to_string());

        create_organization(&server, "LotR", &lotr_user_credentials);

        server
    }

    fn authenticate_clients_for_server(server: &Server) -> Vec<AuthenticatedClient> {
        vec![
            ("Aperture Science", "Chell", "chellpassword", "Cave", "cavepassword"),
            ("Star Wars", "Luke", "lukepassword", "Leila", "leilapassword"),
            ("LotR", "Gandalf", "gandalfpassword", "Frodo", "frodopassword"),
        ]
            .iter()
            .map(|(organization, user1, password1, user2, password2)|
                unlock_vault_for_organization(&server, organization, user1, password1, user2, password2))
            .collect()
    }

    fn set_up_server_with_organizations_and_documents() -> (Server, Vec<AuthenticatedClient>) {
        let server = set_up_server_with_organizations();
        let clients = authenticate_clients_for_server(&server);


        let document = Document {
            name: "aperture science 1".to_string(),
            content: "aperture science content 1".to_string(),
        };
        make_client_upload_document_to_server(&document, &clients[0], &server);

        let document = Document {
            name: "aperture science 2".to_string(),
            content: "aperture science content 2".to_string(),
        };
        make_client_upload_document_to_server(&document, &clients[0], &server);

        let document = Document {
            name: "aperture science star wars shared".to_string(),
            content: "shared content".to_string(),
        };
        make_client_upload_document_to_server(&document, &clients[0], &server);
        let document_id = get_id_of_document_by_name("aperture science star wars shared", &clients[0], &server).unwrap();
        make_client_share_document(&document_id, "Star Wars", &clients[0], &server);

        let document = Document {
            name: "star wars".to_string(),
            content: "star wars content".to_string(),
        };
        make_client_upload_document_to_server(&document, &clients[1], &server);

        (server, clients)
    }

    #[test]
    fn unlock_vault() {
        let server = set_up_server_with_organizations();
        authenticate_clients_for_server(&server);
    }

    #[test]
    fn delete_user() {
        let server = set_up_server_with_organizations();
        let clients = authenticate_clients_for_server(&server);

        server.revoke_user(&clients[1].token, "Darth Vador").unwrap();

        assert_eq!(None, server.unlock_vault("Star Wars", "Darth Vador", "Leila"));
    }

    #[test]
    fn delete_user_wrong_token() {
        let server = set_up_server_with_organizations();
        let clients = authenticate_clients_for_server(&server);

        assert_eq!(None, server.revoke_user(&clients[2].token, "Darth Vador"));

        unlock_vault_for_organization(
            &server, "Star Wars",
            "Darth Vador", "darthvadorpassword",
            "Leila", "leilapassword",
        );
    }

    #[test]
    fn list_documents() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let organization0_documents = server.list_documents(&clients[0].token).unwrap();
        assert_eq!(3, organization0_documents.len());
        clients[0].find_document_id_from_name(&organization0_documents, "aperture science 1").unwrap();
        clients[0].find_document_id_from_name(&organization0_documents, "aperture science 2").unwrap();
        clients[0].find_document_id_from_name(&organization0_documents, "aperture science star wars shared").unwrap();

        let organization1_documents = server.list_documents(&clients[1].token).unwrap();
        assert_eq!(2, organization1_documents.len());
        clients[1].find_document_id_from_name(&organization1_documents, "star wars").unwrap();
        clients[1].find_document_id_from_name(&organization1_documents, "aperture science star wars shared").unwrap();

        let organization2_documents = server.list_documents(&clients[2].token).unwrap();
        assert_eq!(0, organization2_documents.len());
    }

    #[test]
    fn list_documents_wrong_token() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        assert_eq!(None, server.list_documents(&Vec::<u8>::new()));
    }

    #[test]
    fn get_document_key_wrong_token() {
        let (server, clients) = set_up_server_with_organizations_and_documents();
        let id_of_document_not_owned_by_organization_2 = get_id_of_document_by_name("aperture science 1", &clients[0], &server).unwrap();
        assert_eq!(None, server.get_document_key(&clients[2].token, &id_of_document_not_owned_by_organization_2));
    }

    #[test]
    fn get_document() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let document1 = make_client_get_document_from_server_by_name("aperture science 1", &clients[0], &server);
        assert_eq!(document1, Document { name: "aperture science 1".to_string(), content: "aperture science content 1".to_string() });

        let document2 = make_client_get_document_from_server_by_name("aperture science 2", &clients[0], &server);
        assert_eq!(document2, Document { name: "aperture science 2".to_string(), content: "aperture science content 2".to_string() });

        let document3 = make_client_get_document_from_server_by_name("aperture science star wars shared", &clients[0], &server);
        assert_eq!(document3, Document { name: "aperture science star wars shared".to_string(), content: "shared content".to_string() });

        let document4 = make_client_get_document_from_server_by_name("aperture science star wars shared", &clients[1], &server);
        assert_eq!(document4, Document { name: "aperture science star wars shared".to_string(), content: "shared content".to_string() });

        let document5 = make_client_get_document_from_server_by_name("star wars", &clients[1], &server);
        assert_eq!(document5, Document { name: "star wars".to_string(), content: "star wars content".to_string() });
    }

    #[test]
    fn get_document_wrong_token() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let id_of_document_not_owned_by_organization_2 = get_id_of_document_by_name("aperture science 1", &clients[0], &server).unwrap();
        assert_eq!(None, server.download_document(&clients[2].token, &id_of_document_not_owned_by_organization_2));
    }

    #[test]
    fn update_document() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let document_id = get_id_of_document_by_name("aperture science 1", &clients[0], &server).unwrap();

        let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
        make_client_update_document_on_server(&document_id, &new_document, &clients[0], &server).unwrap();

        let downloaded_document = make_client_get_document_from_server(&document_id, &clients[0], &server);
        assert_eq!(new_document, downloaded_document);
    }

    #[test]
    fn update_shared_document() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let document_id = get_id_of_document_by_name("aperture science star wars shared", &clients[0], &server).unwrap();

        let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
        make_client_update_document_on_server(&document_id, &new_document, &clients[0], &server).unwrap();

        let downloaded_document = make_client_get_document_from_server(&document_id, &clients[1], &server);
        assert_eq!(new_document, downloaded_document);
    }

    #[test]
    fn update_document_wrong_token() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let document_id = get_id_of_document_by_name("aperture science 1", &clients[0], &server).unwrap();

        let original_document = make_client_get_document_from_server(&document_id, &clients[0], &server);
        let new_document = Document { name: "new name".to_string(), content: "new content".to_string() };
        assert_eq!(None, make_client_update_document_on_server(&document_id, &new_document, &clients[2], &server));

        let downloaded_document = make_client_get_document_from_server(&document_id, &clients[0], &server);
        assert_eq!(original_document, downloaded_document);
    }

    #[test]
    fn delete_document() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let deleted_document_id = get_id_of_document_by_name("aperture science 1", &clients[0], &server)
            .unwrap();
        server.delete_document(&clients[0].token, &deleted_document_id).unwrap();

        let documents_list = server.list_documents(&clients[0].token).unwrap();
        let document_ids: Vec<DocumentID> = documents_list.keys().cloned().collect();
        assert!(!document_ids.contains(&deleted_document_id));

        assert_eq!(None, server.download_document(&clients[0].token, &deleted_document_id));
    }

    #[test]
    fn delete_shared_document() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let deleted_document_id = get_id_of_document_by_name("aperture science star wars shared", &clients[0], &server)
            .unwrap();
        server.delete_document(&clients[0].token, &deleted_document_id).unwrap();

        let documents_list = server.list_documents(&clients[1].token).unwrap();
        let document_ids: Vec<DocumentID> = documents_list.keys().cloned().collect();
        assert!(document_ids.contains(&deleted_document_id));

        server.download_document(&clients[1].token, &deleted_document_id).unwrap();
    }

    #[test]
    fn delete_document_wrong_token() {
        let (server, clients) = set_up_server_with_organizations_and_documents();

        let deleted_document_id = get_id_of_document_by_name("aperture science star wars shared", &clients[0], &server)
            .unwrap();
        assert_eq!(None, server.delete_document(&clients[1].token, &deleted_document_id));

        let documents_list = server.list_documents(&clients[0].token).unwrap();
        let document_ids: Vec<DocumentID> = documents_list.keys().cloned().collect();
        assert!(document_ids.contains(&deleted_document_id));

        server.download_document(&clients[0].token, &deleted_document_id).unwrap();
    }
}