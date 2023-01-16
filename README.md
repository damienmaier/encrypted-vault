# Encrypted Vault
This is a client-server application that provides an online vault for organizations that need to store very sensitive documents.

The client and the server are both written in Rust.

## Description and usage

A single server (online vault) can be used by several client organizations. Each organization can store documents on the server.

### Documents storage on the server
- The server never sees the documents in clear and is not able to recover them (assuming “good” passwords).
- If a document’s encryption key leaks, it does not allow to decrypt other documents.
### Unlocking the vault
- Before accessing the vault, the client needs to authenticate. Two people out of n need to gather to access the vault. The process is the following:
    1. The company sends its company name to the server. 
    2. Then, two members of the company (out of n) enter their credentials (username + password) to unlock the vault.
- The client does not need to enter more than one password per member.
- Clients can connect to the vault from any computer and change device as they want. No data is stored on the client side.
- A client can revoke one of its users. This does not require the re-encryption of the documents.
### Documents access
- Each document on the server is owned by one or several clients.
- A client can upload a document on the server. This makes him an owner of this document.
- Any owner of a document can add another client as owner of the document.
- Any owner of a document can download it or upload an updated version of the document.
- Any owner of a document can delete a document (for himself). If other clients own the document, they can still access it.

### Security assumptions

- There is an active adversary between the client and the server.
- Users can not dump the memory of the client software.

## Security design

[Security design](implementation.md)

## Cryptographic primitives

[Cryptographic primitives](cyptography_primitives.md)

## What is implemented

- A fully functional server, that stores its data in files on the disk
- The "backend" for a client, i.e. a set of structs and functions that are expected to be called from a user interface
- Integration tests, that automatically run server instances and call functions from the client backend
- A basic and ugly command line client application

## How to build and run this project

### TLS certificates

The client and the server need certificates originating from a PKI.

- Place your PKI **root certificate** in `<project root>/client_files/root_certificate.pem`
- Place the **server certificate** signed by the root certificate in `<project root>/server_files/server_certificate.pem`
- Place the **private key** associated with the server certificate in `<project root>/server_files/server_certificate_key.key`

If you just want to test this application and need a server certificate for `localhost`, you can create the appropriate certificates by running the following commands :

```shell
mkdir client_files
mkdir server_files

openssl req -x509 -days 365 -subj "/C=/ST=/L=/O=/CN=vaultroot" -addext basicConstraints=critical,CA:true -nodes -out client_files/root_certificate.pem -keyout root_certificate_private_key.key
openssl req -CA client_files/root_certificate.pem -CAkey root_certificate_private_key.key -subj "/C=/ST=/L=/O=/CN=localhost" -addext basicConstraints=critical,CA:false -nodes -out server_files/server_certificate.pem -keyout server_files/server_certificate_key.key
```

This :

- Creates a CA certificate
- Creates a leaf certificate signed by the CA certificate, for the name `localhost`

### Configuration files

The server reads its configuration from `<project root>/server_files/config`. The client reads its configuration from `<project root>/client_files/config`.

If those files do not exist, they are automatically created with some default values.

### Running the server

```shell
cargo run --bin server
```

### Running the client

```shell
cargo run --bin client
```