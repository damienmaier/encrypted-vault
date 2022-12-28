# Encrypted Vault
This is a web application that provides an online vault for organizations that need to store very sensitive documents.

The web server is written in Rust. The client side code is written in WebAssembly compiled Rust that runs in the browser.

## Description and usage

A single server (online vault) can be accessed by several client organizations. Each organization can store documents on the server.

### Documents storage on the server
- The server never sees the documents in clear and is not able to recover them (assuming “good” passwords).
- If a document’s encryption key leaks, it does not allow to decrypt other documents.
- If a document’s encryption key leaks, it does not allow to decrypt other documents.
### Unlocking the vault
- Before accessing the vault, the client needs to authenticate. Two people out of n need to gather to access the vault. The process is the following:
    1. The company sends its company name to the server. 
    2. Then, two members of the company (out of n) enter their credentials (username + password) to unlock the vault.
- The client does not need to enter more than one password per member.
- Clients can connect to the vault from any computer and change device as they want.
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

## Cryptography

In all the diagrams below, **the data in red is stored on the server**.

**All other data** is computed by the client and **only exists in the client's memory**.

### Encryption of the data stored on the server

In all the diagrams below, a dotted arrow between a key and some data stored on the server, like this :

![](readme-images/dotted%20arrow%20example.drawio.png)

means that, instead of storing the data B, we store **ENC<sub>key A</sub>(data B)** on the server.

#### Encryption algorithm

ENC is the authenticated encryption algorithm **XSalsa20 + Poly1305 MAC**.

#### Key

All keys are 256 bits long.

#### Nonce

The nonce is 192 bits long and is chosen randomly.

For a given key, the nonce collision probability stays below 2<sup>-32</sup> as long as the number of encryptions is lower than 2<sup>80</sup> (birthday problem). Even if we did 1'000'000'000 encryptions par second for 100 years, this would still result in less than 2<sup>62</sup> encryptions. Thus, the risk of collision is negligible.

The nonce is stored alongside the encrypted data.

