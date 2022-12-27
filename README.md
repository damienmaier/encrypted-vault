# Encrypted Vault
This is a web application that provides an online vault for companies that need to store very sensitive files.

The server and the client are written in Rust.
## Requirements
### Documents storage on the server
- The server should never see the documents in clear and should not be able to recover them (assuming “good” passwords).
- If a document’s encryption key leaks, one should not be able to decrypt other documents.
### Client authentication
- Before accessing the vault, the client needs to authenticate. Two people out of n need to gather to access the vault. The process is the following:
    1. The company sends its company name to the server. 
    2. Then, two members of the company (out of n) enter their credentials (username + password) to unlock the vault.
- The client should not have to enter more than one password per member.
- Clients should be able to connect to the vault from any computer and change device as they want.
- You need to be able to revoke a user. This should not require the re-encryption of all files.
### Documents access
- Several client companies can store documents on the server.
- Each document on the server is owned by one or several clients.
- A client can upload a document on the server. This makes him the owner of this document.
- Any owner of a document can add another client as owner of the document.
- Any owner of a document can download it, upload an updated version or delete the document.

### Security assumptions

- There is an active adversary between the client and the server.
- A user can not dump the memory of the client software.

## Cryptography

In all the diagrams below, the data in red is stored on the server. All other data is computed by the client and only exists in the client's memory.

### Encryption of the data stored on the server

In all the diagrams below, a dotted arrow between a key and some data stored on the server, like this :

![](readme-images/dotted%20arrow%20example.drawio.png)

means that, instead of storing the data B, we store **ENC<sub>key A</sub>(data B)** on the server.

#### Encryption algorithm

ENC is the authenticated encryption algorithm **XSalsa20 + Poly1305 MAC**.

#### Key

All keys are 256 bits long.

#### Nonce

The nonce is 192 bit longs and is chosen randomly.

For a given key, the nonce collision probability stays below 2<sup>-32</sup> as long as the number of encryptions is lower than 2<sup>80</sup> (birthday problem). Even if we did 1'000'000'000 encryptions par second for 100 years, this would only result in less than 2<sup>62</sup> encryptions. Thus, the risk of collision is negligible.