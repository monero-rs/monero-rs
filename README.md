Rust Monero Library
===

Library with support for de/serialization, parsing and executing on data structures and network messages related to Monero currency.

Supports (or should support)

 * De/serialization of Monero blocks and transactions
 * Address and subaddress creation, de/serialization and validation
 * Private keys and one-time keys creation, de/serialization and validation

Contributing
===

Contributions are welcome.

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

## Building for WASM

This library can be built to target wasm platform with:

```
cargo build --target wasm32-unknown-unknown
```

About
===

This is a research project sponsored by TrueLevel, developed by h4sh3d.
