[![Build Status](https://img.shields.io/github/actions/workflow/status/monero-rs/monero-rs/ci.yml?branch=main)](https://github.com/monero-rs/monero-rs/actions/workflows/ci.yml)
[![Codecov branch](https://img.shields.io/codecov/c/gh/monero-rs/monero-rs/main)](https://app.codecov.io/gh/monero-rs/monero-rs)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Crates.io](https://img.shields.io/crates/v/monero.svg)](https://crates.io/crates/monero)
[![Documentation](https://docs.rs/monero/badge.svg)](https://docs.rs/monero)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-blue)](https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html)

# Rust Monero Library

Library with support for de/serialization on block data structures and key/address generation and scanning related to Monero cryptocurrency.

Supports (or should support)

- De/serialization of Monero blocks and transactions (consensus encoding)
- Address and subaddress creation, de/serialization and validation
- Private keys and one-time keys creation, de/serialization and validation
- Transaction owned output detection and amount recovery with view keypair
- Serde support on most structures with feature `serde`

## Documentation

Currently can be found on [docs.rs/monero](https://docs.rs/monero). Patches to add usage examples and to expand on existing docs would be extremely appreciated.

## Features

### `serde`

The `serde` feature enables implementation of [`serde`](https://docs.rs/serde/latest/serde/) on serializable types across the library.

### `experimental`

The `experimental` feature enable the method `signature_hash` in `Transaction`, the method computes the message to be signed by the CLSAG signature algorithm. This method is featured as experimental at the moment because it lacks reviews and tests.

## Contributing

Contributions are generally welcome. If you intend to make larger changes please discuss them in an issue before PRing them to avoid duplicate work and architectural mismatches.

## Releases and Changelog

See [CHANGELOG.md](CHANGELOG.md) and [RELEASING.md](RELEASING.md).

## About

This started as a research project sponsored by TrueLevel SA, it is now developed and maintained by the Monero Rust Contributors and NOT by the Monero Core Team.

## Licensing

The code in this project is licensed under the [MIT License](LICENSE)
