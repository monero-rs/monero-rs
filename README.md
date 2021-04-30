[![Build Status](https://img.shields.io/github/workflow/status/monero-rs/monero-rs/CI/main)](https://github.com/monero-rs/monero-rs/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Crates.io](https://img.shields.io/crates/v/monero.svg)](https://crates.io/crates/monero)
[![Documentation](https://docs.rs/monero/badge.svg)](https://docs.rs/monero)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust Monero Library
===

Library with support for de/serialization on block data structures and key/address generation and scanning related to Monero cryptocurrency.

Supports (or should support)

 * De/serialization of Monero blocks and transactions (consensus encoding)
 * Address and subaddress creation, de/serialization and validation
 * Private keys and one-time keys creation, de/serialization and validation
 * Transaction owned output detection and amount recovery with view keypair
 * Serde support on most structures with feature `serde_support`
 * Strict encoding support on most structures with feature `strict_encoding_support`

### `serde` Support

The `serde_support` feature enables implementation of `serde` on serializable types.

### `strict_encoding` Support

The `strict_encoding_support` feature enables `StrictEncode` and `StrictDecode` trait implementation for a few types that implements `consensus::Encodable` and `consensus::Decodable`.

`strict_encoding` is a wrapper that allows multiple consensus encoding to work under the same interface, i.e. `StrictEncode` and `StrictDecode`.

## Documentation

Currently the documentation is very sparse. Patches to add usage examples and to expand on existing docs would be extremely appreciated.

Contributing
===

Contributions are generally welcome. If you intend to make larger changes please discuss them in an issue before PRing them to avoid duplicate work and architectural mismatches.

About
===

This started as a research project sponsored by TrueLevel SA, it is now developed and maintained by h4sh3d and member's of the community and NOT by the Monero Core Team.
