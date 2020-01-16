[![Build Status](https://travis-ci.com/monero-rs/monero-rs.svg?branch=master)](https://travis-ci.com/monero-rs/monero-rs) [![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) [![Crates.io](https://img.shields.io/crates/v/monero.svg)](https://crates.io/crates/monero) [![Documentation](https://docs.rs/monero/badge.svg)](https://docs.rs/monero) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust Monero Library
===

Library with support for de/serialization, parsing and executing on data structures and network messages related to Monero currency.

Supports (or should support)

 * De/serialization of Monero blocks and transactions (consensus encoding)
 * Address and subaddress creation, de/serialization and validation
 * Private keys and one-time keys creation, de/serialization and validation
 * Serde support on most structures with feature `serde_support`

## Documentation

Currently the documentation is very sparse. Patches to add usage examples and to expand on existing docs would be extremely appreciated.

Contributing
===

Contributions are generally welcome. If you intend to make larger changes please discuss them in an issue before PRing them to avoid duplicate work and architectural mismatches.

## Building

The library can be built and tested using cargo:

```
git clone git@github.com:monero-rs/monero-rs.git
cd monero-rs
cargo build
```

You can run tests with:

```
cargo test
```

About
===

This started as a research project sponsored by TrueLevel SA, it is now developed and maintained by h4sh3d and member's of the community and not by the Monero Core Team.
