# Operation

## Client server communication

All communications between the client and the server are done using an HTTPS API.

As the client organization must be able to access the vault from any device, the server uses a certificate issued by a recognized certificate authority.

| Action                  | Data sent with the request                                                  | Data sent with the response                                                       | Authentication token required | Restriction                                                      |
|-------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------|-------------------------------|------------------------------------------------------------------|
| Client account creation | Organization name, user names, encrypted private key shares, public key     |                                                                                   | no                            |                                                                  |
| Unlock vault            | Organization name, 2 user names                                             | 2 encrypted private key shares, encrypted token, public keys of all organizations | no                            |                                                                  |
| Revoke user             | User name                                                                   |                                                                                   | yes                           | At least 2 users must remain after the revocation                |
| New document            | Encrypted document key, encrypted document name, encrypted document content |                                                                                   | yes                           |                                                                  |
| List documents          |                                                                             | Document IDs, encrypted document keys, encrypted document names                   | yes                           |                                                                  |
| Get document key        | Document ID                                                                 | Encrypted document key                                                            | yes                           | The client associated to the token must be owner of the document |
| Download document       | Document ID                                                                 | Encrypted document name and content                                               | yes                           | The client associated to the token must be owner of the document |
| Update document         | Document ID, encrypted document name, encrypted document content            |                                                                                   | yes                           | The client associated to the token must be owner of the document |
| Delete document         | Document ID                                                                 |                                                                                   | yes                           | The client associated to the token must be owner of the document |
| Add owner               | Document ID, other organization name, encrypted document key                |                                                                                   | yes                           | The client associated to the token must be owner of the document |

## Client organization public / private key pair

Each client organization has an associated **private / public key pair**. This pair of keys is what allows the client to encrypt and decrypt the data stored on the server. Retrieving public / private key pair is the first thing the client does when he accesses the vault.

The public / private key pair of an organization never changes.

### Data stored on the server

For each client organization, the server stores a list of usernames and encrypted private key shares. It also stores the public key of the organization.

![](readme-images/Storage%20root%20key%20shares.drawio.png)

### Public / private key creation

When a client organization is created, the following process takes place :

- All users of the client organization provide their username and password to the client software.
- The client software applies the **Argon2** algorithm on each password to obtain the symmetric **user derived keys**.
- The client software generates a public / private key pair for the organization.
- The client software uses the **shamir secret sharing** algorithm to generate one **private key share** for each user, where 2 shares are enough to recover the private key.
- The client software encrypts each share with the corresponding user derived key.
- The client software stores the encrypted shares, the associated usernames and the public key on the server.

### Public / private key retrieving

To retrieve the key pair, the client follows the following process :

- Two users provide their username and password to the client software.
- The client software obtains the two **user derived keys** by applying the Argon2 algorithm on each password.
- The client software gets the two **encrypted private key shares** associated to both users and the **public key** from the server.
- The client software performs decryption using the user derived keys, and obtains the two **private key shares**.
- The client software uses the shamir secret sharing algorithm to obtain the **private key**.

### User revocation

To revoke a user, the client software deletes the user's encrypted private key share from the server.

## Authentication token

Each client organization that has unlocked the vault has an associated **token**. This token must be provided with certain requests to the server, in order to authenticate the client.

When the server receives a vault unlock request from a client, it generates a random token and keeps it in memory, along with the client organization name. It encrypts the token with the client organization public key and sends the encrypted token to the client.

By providing the decrypted token in its subsequent requests, the client proves its identity.

## Documents

### Data stored on the server

#### Documents

Each document is associated to a symmetric document key. For each document, the server stores its id, its encrypted name and its encrypted content.

![](readme-images/Storage%20documents.drawio.png)

#### Document keys

For a given client, the server stores a list of the IDs of the documents owned by this client, and the corresponding document keys. The document keys are encrypted with the client public key.

![](readme-images/Storage%20document%20keys.drawio.png)

### New document upload

When a client uploads a new file, the following process takes place :

- The client randomly choses a symmetric document key.
- The client encrypts the document name and the document content with the document key.
- The client encrypts the document key with the public key.
- The client requests the server to store the encrypted document key, the encrypted document name and the encrypted document content.
- The server choses an ID for the new document, stores the encrypted document name and content and adds the ID and encrypted document key to the list of documents owned by the client.

### Retrieve document list

When a client wants to get le list of its files, the following process takes place :
- The client requires the server to send the id, document key and document name of all the files owned by the client
- The client uses its private key to decrypt the document keys
- The client uses the document keys to decrypt the document names

### Document download

When a client downloads a document :
- The client requests the encrypted document key from the server
- The client requests the encrypted document name and content from the server
- The client decrypts the document key with its private key
- The client decrypts the document name and content with the document key

### Document update

When a client uploads a new version of an existing document :
- The client requests the encrypted document key from the server
- The client decrypts the document key with its private key
- The client encrypts the new document name and the new document content with the document key
- The client requests the server to store the new encrypted document name and content

### Delete a document

When a client deletes a document :
- The client requests the server to delete the document key from the client's document key list
- The server checks if another client owns the document. If this is not the case, the server also deletes the document.

### Add another client as owner of the document

- The client requests the encrypted document key from the server
- The client decrypts the document key with its private key
- The client encrypts the document key with the public key of the other organization
- The client requests the server to store the newly encrypted document key in the list of documents owned by the other organization.