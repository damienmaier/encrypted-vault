extern crate core;

use dialoguer::PasswordInput;
use read_input::{InputBuild, InputConstraints};
use read_input::prelude::input;
use vault::client::client_config::ClientConfig;
use vault::client::http_connection::HttpConnection;
use vault::client::organization_creation::{empirically_choose_argon_config, OrganizationBuilder};
use vault::client::session_controller::Controller;
use vault::data::Document;
use vault::error::VaultError;
use vault::error::VaultError::InputError;


fn main() {
    let choice: u8 = input()
        .msg("\
Welcome to the vault software !
Please choose an option:

1. Create a new organization
2. Log in
")
        .inside([1, 2])
        .get();

    if choice == 1 {
        if let Err(error) = create_new_organization() {
            println!("{error:?}");
        }
    } else {
        if let Err(error) = log_in() {
            println!("{error:?}");
        }
    }
}


fn create_new_organization() -> Result<(), VaultError> {
    let organization_name: String = input()
        .msg("Please enter your organization name: ")
        .get();

    println!("We are now going to choose the password hashing cost parameters for your organization.");
    println!("The hashing cost will be automatically chosen such that computing a hash takes around 10 seconds on this computer.");
    println!("Beware that the hashing time depends on the performance of the computer you use to run the client software.");
    println!("Thus, if you plan to connect to the vault using a computer much slower than this one, computing a hash will take more time.");

    let argon_memory_cost_mb: usize = input()
        .msg("Please choose the amount of memory that the hashing process will use (in gigabytes)")
        .min(1)
        .get();

    let argon_config = empirically_choose_argon_config(argon_memory_cost_mb * 1_000_000)?;

    let mut organization_builder = OrganizationBuilder::new(&organization_name, &argon_config)?;

    loop {
        let username: String = input()
            .msg("Username: ")
            .get();

        let password = PasswordInput::new().with_prompt("New Password")
            .with_confirmation("Confirm password", "Passwords mismatching")
            .interact().map_err(|_| InputError)?;

        organization_builder = organization_builder.add_user(&username, &password)?;

        println!("Do you want to add a user ?");
        println!("1. yes");
        println!("2. no");
        let choice: u8 = input().inside([1, 2]).get();
        if choice == 2 {
            break;
        }
    }

    let mut server = HttpConnection::new(ClientConfig::get().server_port);

    println!("Please wait...");
    organization_builder.create_organization(&mut server)?;

    println!("Success");
    Ok(())
}

fn log_in() -> Result<(), VaultError> {
    let organization_name: String = input()
        .msg("Organization name: ")
        .get();

    let username1: String = input()
        .msg("username: ")
        .get();

    let password1 = PasswordInput::new().with_prompt("password")
        .interact().map_err(|_| InputError)?;

    let username2: String = input()
        .msg("username: ")
        .get();

    let password2 = PasswordInput::new().with_prompt("password")
        .interact().map_err(|_| InputError)?;

    let mut server = HttpConnection::new(ClientConfig::get().server_port);

    let mut controller = Controller::unlock_vault_for_organization(&mut server, &organization_name, &username1, &password1, &username2, &password2)?;

    println!("You have unlocked the vault !");

    loop {
        let choice: u8 = input()
            .msg("


Please choose an option:
1. Revoke user
2. Upload new document
3. List documents
4. Download document
5. Update document
6. Share document
7. Delete document
8. Exit
")
            .inside([1, 2, 3, 4, 5, 6, 7])
            .get();

        match choice {
            1 => revoke_user(&mut controller)?,
            2 => upload(&mut controller)?,
            3 => list(&mut controller)?,
            4 => download(&mut controller)?,
            5 => update(&mut controller)?,
            6 => share(&mut controller)?,
            7 => delete(&mut controller)?,
            8 => break,
            _ => panic!()
        }
    }

    Ok(())
}

fn revoke_user(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {
    let username: String = input().msg("user: ").get();
    controller.revoke_user(&username)?;
    Ok(())
}

fn upload(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {
    let name = input().msg("document name: ").get();
    let content = input().msg("document content: ").get();


    controller.upload(&Document { name, content })?;
    Ok(())
}

fn download(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {
    let name: String = input().msg("document name: ").get();

    let document = controller.download(&name)?;

    println!("name: {}", document.name);
    println!("content: {}", document.content);

    Ok(())
}

fn list(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {
    for name in controller.list_document_names()?{
        println!("{name}");
    }

    Ok(())
}

fn update(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {
    let old_name:String = input().msg("old document name: ").get();

    let name = input().msg("document name: ").get();
    let content = input().msg("document content: ").get();

    controller.update(&old_name, &Document { name, content })?;

    Ok(())
}

fn share(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {

    let document_name: String = input().msg("document name: ").get();
    let other_organization_name:String = input().msg("other organization name: ").get();

    controller.share(&document_name, &other_organization_name)?;

    Ok(())
}

fn delete(controller: &mut Controller<HttpConnection>) -> Result<(), VaultError> {

    let document_name: String = input().msg("document name: ").get();

    controller.delete(&document_name)?;

    Ok(())
}