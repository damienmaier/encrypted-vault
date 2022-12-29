# Cryptographic primitives

## Symmetric encryption

### Encryption algorithm

We use the Rust module [dryoc::dryocsecretbox](https://docs.rs/dryoc/latest/dryoc/dryocsecretbox/index.html) that implements the authenticated encryption algorithm **XSalsa20 + Poly1305 MAC**

#### Nonce

The nonce is 192 bits long and is chosen randomly.

For a given key, the nonce collision probability stays below 2<sup>-32</sup> as long as the number of encryptions is lower than 2<sup>80</sup> (birthday problem). Even if we did 1'000'000'000 encryptions par second for 100 years, this would still result in less than 2<sup>62</sup> encryptions. Thus, the risk of nonce collision is negligible.

The nonce is stored alongside the encrypted data.

## Asymmetric encryption

### Encryption algorithm

We use the `DryocBox::seal` and `DryocBox::unseal` functions of the Rust module [dryoc::dryocbox](https://docs.rs/dryoc/latest/dryoc/dryocbox/index.html).

It implements an hybrid encryption algorithm where **X25519** is used to derive a symmetric key that is then used to encrypt with **XSalsa20** and compute a MAC with **Poly1305**.


## Shamir secret sharing

We use the implementation provided by the crate [sharks](https://docs.rs/sharks/latest/sharks/).

## Argon2

We use the Rust module [dryoc::pwhash](https://docs.rs/dryoc/latest/dryoc/pwhash/index.html)

TODO cost parameters

## Randomness

All the random values are chosen using the randomness provided by the OS.

For the nonces, symmetric keys and asymmetric keys, this is done by using `dryoc::dryocsecretbox::Nonce::gen()`, `dryoc::dryocsecretbox::Key::gen()`, `dryoc::dryocbox::Nonce::gen()` and `dryoc::dryocbox::KeyPair::gen()`. Those functions internally use [rand::rngs::OsRng](https://docs.rs/rand/0.5.0/rand/rngs/struct.OsRng.html), which is an RNG that retrieves randomness from the OS.

The salts and authentication tokens are chosen using `dryoc::rng`, which also uses [rand::rngs::OsRng](https://docs.rs/rand/0.5.0/rand/rngs/struct.OsRng.html).


## TLS

TODO