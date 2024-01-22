# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in [The Cargo Book](https://doc.rust-lang.org/cargo/reference/manifest.html#the-version-field).

## [Unreleased]

## [0.20.0] - 2024-01-22

### Added

- Extended fuzzing test framework with failing unit tests blanked out [@hansieodendaal](https://github.com/hansieodendaal)([#182](https://github.com/monero-rs/monero-rs/pull/182))

### Fixed

- Use both transaction public keys when scanning outputs & reject non-canonical public keys in the tx-extra by [@Boog900](https://github.com/Boog900) ([#180](https://github.com/monero-rs/monero-rs/pull/180))
- Error on non-minimal varint encoding and fix silent overflow [@stringhandler](https://github.com/stringhandler)([#174](https://github.com/monero-rs/monero-rs/pull/174))
- Avoid prepending VarInt length of the blockhashing blob when using `Block::serialize_hashable()` [@parazyd](https://github.com/parazyd)([#194](https://github.com/monero-rs/monero-rs/pull/194))
- Error out of bounds panics in `src/util/address.rs` for `from_bytes` and `from_slice` with fix [@hansieodendaal](https://github.com/hansieodendaal)([#185](https://github.com/monero-rs/monero-rs/pull/185))
- Removed unused output types (and unused `pub fn get_pubkeys`), fixing panic when hashing transactions with those outputs [@hansieodendaal](https://github.com/hansieodendaal)([#186](https://github.com/monero-rs/monero-rs/pull/186))
- Error on extra data parse where `Padding(255)` could not be parsed successfully and where the length returned from parsing
  `SubField::MysteriousMinerGate` was incorrect with fix [@hansieodendaal](https://github.com/hansieodendaal)([#184](https://github.com/monero-rs/monero-rs/pull/184))
- Fixed memory overflow and subtract with overflow when deserializing [@hansieodendaal](https://github.com/hansieodendaal)([#183](https://github.com/monero-rs/monero-rs/pull/183))
- Fixed tx scanning for txs with view tags and lots of outputs (some miner txs) [@Boog900](https://github.com/Boog900) ([#197](https://github.com/monero-rs/monero-rs/pull/197))

## [0.19.0] - 2023-09-15

### Changed

- Exposed `serialize_hashable` on `Block` by [@Boog900](https://github.com/Boog900) ([#143](https://github.com/monero-rs/monero-rs/pull/143))
- Update `base58-monero` to version `2` by [@h4sh3d](https://github.com/h4sh3d) ([#175](https://github.com/monero-rs/monero-rs/pull/175))
- Bump MSRV to version `1.63.0` by [@h4sh3d](https://github.com/h4sh3d) ([#175](https://github.com/monero-rs/monero-rs/pull/175))

## [0.18.2] - 2023-01-02

### Changed

- Allow more amount denomination variants (e.g `xmr|XMR|monero`), prefer lower case in `Display` by @h4sh3d ([#141](https://github.com/monero-rs/monero-rs/pull/141))

## [0.18.1] - 2022-12-13

### Added

- Tree hash algorithm to compute tree hash as defined by Cryptonote by [@vorot93](https://github.com/vorot93) ([#130](https://github.com/monero-rs/monero-rs/pull/130))

### Changed

- Minimum Supported Rust Version is now `1.56.1` and `edition 2021` is enabled by [@vorot93](https://github.com/vorot93) ([#125](https://github.com/monero-rs/monero-rs/pull/125))
- Update `fixed-hash` version to `0.8.0` by [@vorot93](https://github.com/vorot93) ([#125](https://github.com/monero-rs/monero-rs/pull/125))

### Fixed

- Fix deserialization of certain `ExtraField` fields and remove the need for the extra data to be parsable by [@Boog900](https://github.com/Boog900) ([#123](https://github.com/monero-rs/monero-rs/pull/123)) and [@vorot93](https://github.com/vorot93) ([#136](https://github.com/monero-rs/monero-rs/pull/136))
- Deserialization of transactions with outputs to invalid points on Edwards curve [@Boog900](https://github.com/Boog900) ([#132](https://github.com/monero-rs/monero-rs/pull/132))

## [0.18.0] - 2022-09-05

### Added

- Change `u64` and `VarInt` to `Amount` where it makes sense to by [@LeoNero](https://github.com/LeoNero) ([#113](https://github.com/monero-rs/monero-rs/pull/113))
- Add `FromHex` for `Hash`, `Hash8`, `PaymentId`, and `Address` [@LeoNero](https://github.com/LeoNero) ([#114](https://github.com/monero-rs/monero-rs/pull/114))
- Add `ToHex` for `Address` [@LeoNero](https://github.com/LeoNero) ([#114](https://github.com/monero-rs/monero-rs/pull/114))
- Add support for (de)serialization of BulletproofPlus and view tags by [@Boog900](https://github.com/Boog900) ([#116](https://github.com/monero-rs/monero-rs/pull/116))

### Changed

- Use view tags, when available, to speedup owned output finding by [@Boog900](https://github.com/Boog900) ([#116](https://github.com/monero-rs/monero-rs/pull/116))

## [0.17.3] - 2023-01-02

### Changed

- Allow more amount denomination variants (e.g `xmr|XMR|monero`), prefer lower case in `Display` by @h4sh3d

## [0.17.2] - 2022-07-19

### Added

- Add serde `serialize` for `Amount` and `SignedAmount` slices by [@LeoNero](https://github.com/LeoNero) ([#107](https://github.com/monero-rs/monero-rs/pull/107))
- Add serde `deserialize` for `Amount` and `SignedAmount` vectors by [@LeoNero](https://github.com/LeoNero) ([#107](https://github.com/monero-rs/monero-rs/pull/107))

## [0.17.1] - 2022-07-12

### Added

- Add serde support for `Index` by [@LeoNero](https://github.com/LeoNero) ([#104](https://github.com/monero-rs/monero-rs/pull/104))

### Changed

- Relax generics requirement to `?Sized` in consensus encode/decode reader and writer by [@h4sh3d](https://github.com/h4sh3d) ([#101](https://github.com/monero-rs/monero-rs/pull/101))

## [0.17.0] - 2022-06-29

### Added

- Add serde support for `Amount` by [@TheCharlatan](https://github.com/TheCharlatan) ([#74](https://github.com/monero-rs/monero-rs/pull/74))

### Changed

- Rename feature `serde_support` into `serde` by [@h4sh3d](https://github.com/h4sh3d) ([#94](https://github.com/monero-rs/monero-rs/pull/94))
- Update `base58-monero` requirement from 0.3 to 1 by [@h4sh3d](https://github.com/h4sh3d) ([#91](https://github.com/monero-rs/monero-rs/pull/91))
- Update `serde-big-array` requirement from 0.3.2 to 0.4.1 ([#77](https://github.com/monero-rs/monero-rs/pull/77))
- Update `serde_json` requirement from &lt;1.0.45 to 1 ([#84](https://github.com/monero-rs/monero-rs/pull/84))
- Update `sealed` requirement from 0.3 to 0.4 ([#73](https://github.com/monero-rs/monero-rs/pull/73))

### Fixed

- Check outputs of miner transaction by [@h4sh3d](https://github.com/h4sh3d) ([#96](https://github.com/monero-rs/monero-rs/pull/96))
- Make `Key64` an array of 64 32-byte keys by [@Boog900](https://github.com/Boog900) ([#86](https://github.com/monero-rs/monero-rs/pull/86))

## [0.16.0] - 2021-11-15

### Added

- Method to check outputs with existing `SubKeyChecker` by [@busyboredom](https://github.com/busyboredom) ([#64](https://github.com/monero-rs/monero-rs/pull/64))
- Implement consensus decodable and encodable for `Address` by [@TheCharlatan](https://github.com/TheCharlatan) ([#68](https://github.com/monero-rs/monero-rs/pull/68))

### Removed

- Remove the strict encoding support feature, this should be handled by crates using it, by [@h4sh3d](https://github.com/h4sh3d) ([#67](https://github.com/monero-rs/monero-rs/pull/67))

## [0.15.0] - 2021-09-27

### Added

- Derive `Hash` for `PrivateKey` by [@TheCharlatan](https://github.com/TheCharlatan) ([#58](https://github.com/monero-rs/monero-rs/pull/58))
- Set and test the minimum stable Rust version to `1.51.0` by [@h4sh3d](https://github.com/h4sh3d) ([#60](https://github.com/monero-rs/monero-rs/pull/60))

### Changed

- Modify Hash public API, fix clippy by [@h4sh3d](https://github.com/h4sh3d) ([#59](https://github.com/monero-rs/monero-rs/pull/59))

## [0.14.0] - 2021-08-17

### Added

- Function for computing the signature hash of a transaction by [@COMIT](https://github.com/comit-network) ([#41](https://github.com/monero-rs/monero-rs/pull/41))
- Length bounds check before allocating `Vec` by [@sdbondi](https://github.com/sdbondi) ([#47](https://github.com/monero-rs/monero-rs/pull/47))

### Changed

- Don't use `io::Cursor` for implementing `Encodable` on `ExtraField` by [@COMIT](https://github.com/comit-network) ([#49](https://github.com/monero-rs/monero-rs/pull/49))
- Trait `Encodable` is now sealed and cannot be implemented outside of the library to guarentee a correct, non-failable, implementation, by [@h4sh3d](https://github.com/h4sh3d) ([#50](https://github.com/monero-rs/monero-rs/pull/50))

### Fixed

- Activation of curve25519-dalek's serde feature by [@h4sh3d](https://github.com/h4sh3d) ([#52](https://github.com/monero-rs/monero-rs/pull/52))
- Clippy errors by [@h4sh3d](https://github.com/h4sh3d) ([#53](https://github.com/monero-rs/monero-rs/pull/53))

### Removed

- Unused `TxIn` variants by [@h4sh3d](https://github.com/h4sh3d) ([#50](https://github.com/monero-rs/monero-rs/pull/50))

## [0.13.0] - 2021-06-02

### Added

- `Amount` structure, based on rust-bitcoin implementation by [@h4sh3d](https://github.com/h4sh3d) ([#33](https://github.com/monero-rs/monero-rs/pull/33))

### Changed

- Replace `keccak-hash` with `tiny-keccak` by [@COMIT](https://github.com/comit-network) ([#40](https://github.com/monero-rs/monero-rs/pull/40))
- New `check_output` API by [@COMIT](https://github.com/comit-network) ([#42](https://github.com/monero-rs/monero-rs/pull/42))
- Switch CI from Travis to GitHub Actions

## [0.12.0] - 2021-04-29

### Added

- More types under `strict_encoding` wrapper ([`2dba2da`](https://github.com/monero-rs/monero-rs/commit/2dba2daee9e8bcc90079009279c17ae743794185))
- Add `TryFrom` impl. on keys and more `derive` on some types ([`dd9f1d9`](https://github.com/monero-rs/monero-rs/commit/dd9f1d9e52c31f56edddb111718285a786123bfa), [`06ed856`](https://github.com/monero-rs/monero-rs/commit/06ed856c1c898ec8ca0f3153a730234c98dfb8c4))

### Changed

- Update `base58` dependency to `0.3.0` ([`56c7a0a`](https://github.com/monero-rs/monero-rs/commit/56c7a0a517b0331a80103f0ccc7c1659ec4a6686))
- Change `pub use` over the library ([`0020a6e`](https://github.com/monero-rs/monero-rs/commit/0020a6eadff66c9b677d606868832cfd3944a804))
- Improve overall documentation ([`43c4926`](https://github.com/monero-rs/monero-rs/commit/43c4926b3492fa59f6564e15f9a7014e34b80ce1))

## [0.11.2] - 2021-03-30

### Fixed

- docs.rs compilation errors, add `feature(doc_cfg)` when building on [doc.rs](https://doc.rs)

## [0.11.1] - 2021-03-30

### Added

- Package metadata for generated documentation on [doc.rs](https://doc.rs) to enable feature badges

## [0.11.0] - 2021-03-29

### Added

- Amount recovery for `OwnedTxOut` with `ViewPair` ([#7](https://github.com/monero-rs/monero-rs/issues/7))
- New feature `strict_encoding_support`, disabled by default, which wraps some Encodable and Decodable types

### Changed

- Use `thiserror` on all `Error` types in the library
- Update `base58-monero` to `0.2.1` and upgrade all dependencies
- Simplify `Encodable` and `Decodable` traits based on the work done in [`rust-bitcoin/rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin), remove dependency `bytes`
- Improve README and Rust documentation

## [0.10.0] - 2020-10-16

### Added

- Support for transaction de/serialization with CLSAG signature ([#21](https://github.com/monero-rs/monero-rs/issues/21))

### Changed

- Rename `EcdhInfo::Bulletproof2` into `EcdhInfo::Bulletproof`
- Bump `curve25519-dalek` dependency to version `3`, with optional `serde` support

## [0.9.1] - 2020-09-10

### Added

- Implement `Display` trait for principal structures ([`5d9716f`](https://github.com/monero-rs/monero-rs/commit/5d9716fbdb08e5e6d37103e7fe2b4a45e4c5322b))

## [0.9.0] - 2020-09-04

### Changed

- Removed the deprecated `failure` crate in favour of `thiserror` ([#20](https://github.com/monero-rs/monero-rs/pull/20))

## [0.8.1] - 2020-07-20

### Fixed

- `RctType::Null` deserialization for `RctSigBase` by [@StriderDM](https://github.com/StriderDM) and [@h4sh3d](https://github.com/h4sh3d)

## [0.8.0] - 2020-07-20 [YANKED]

### Changed

- Replaced `std::error::Error` by `Failure` crate by [@sedddn](https://github.com/sedddn)

### Fixed

- Block (de)serialization by ([`db80e61`](https://github.com/monero-rs/monero-rs/commit/db80e61443b430e6da48d0e24f6afd0ef74b79ae))

## [0.7.0] - 2020-03-29

### Changed

- More code examples in documentation

### Fixed

- `check_outputs` behaviour, use ranges for sub-addresses in all cases, reported by [@ladislavdubravsky](https://github.com/ladislavdubravsky)

### Removed

- `SubKeyGenerator`, the implementation is not 100% tested and not needed for reading and parsing transactions

## [0.6.0] - 2020-03-22

### Added

- Methods to recover public and private keys on `OwnedTxOut` ([`c7b5e11`](https://github.com/monero-rs/monero-rs/commit/c7b5e11a0b6ec4c6fecde8e2c4628d9b894edd5b))

### Fixed

- Testnet and Stagenet magic bytes ([`aea9bc0`](https://github.com/monero-rs/monero-rs/commit/aea9bc0f5edd5981544e67b98c6f4211b7958eff))
- One-time key computation, thanks to [@gtklocker](https://github.com/gtklocker) and [@ladislavdubravsky](https://github.com/ladislavdubravsky) ([`c7b5e11`](https://github.com/monero-rs/monero-rs/commit/c7b5e11a0b6ec4c6fecde8e2c4628d9b894edd5b))

## [0.5.0] - 2020-01-16

### Changed

- Finer dependency versions
- Update `dalek` to version `2.0` by [@SWvheerden](https://github.com/SWvheerden)
- Improved documentation and code examples

### Removed

- `cdlyb` and `rlib` attributes ([`28db20c`](https://github.com/monero-rs/monero-rs/commit/28db20c690753e1beac7aaefec20542f042ab276))

## [0.4.0] - 2019-12-04

### Added

- General serde support under `serde_support` feature by [@SWvheerden](https://github.com/SWvheerden)
- Debug and clone derives to most structs by [@SWvheerden](https://github.com/SWvheerden)

## [0.3.0] - 2019-10-02

### Changed

- Update Rust to stable channel instead of nightly by [@vorot93](https://github.com/vorot93)

### Fixed

- Rust format and syntax warnings by [@vorot93](https://github.com/vorot93)

## [0.2.0] - 2019-04-25

### Added

- Serde support for `Address`
- Usage of `fixed-hash` for `cryptonote::hash`
- Code of Conduct

## [0.1.0] - 2019-03-15

### Added

- Initial release of the library
- CI pipeline
- De/serialization of Monero blocks and transactions
- Address and subaddress creation, de/serialization and validation
- Private keys and one-time keys creation, de/serialization and validation

[Unreleased]: https://github.com/monero-rs/monero-rs/compare/v0.20.0...HEAD
[0.20.0]: https://github.com/monero-rs/monero-rs/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/monero-rs/monero-rs/compare/v0.18.2...v0.19.0
[0.18.2]: https://github.com/monero-rs/monero-rs/compare/v0.18.1...v0.18.2
[0.18.1]: https://github.com/monero-rs/monero-rs/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/monero-rs/monero-rs/compare/v0.17.2...v0.18.0
[0.17.3]: https://github.com/monero-rs/monero-rs/compare/v0.17.2...v0.17.3
[0.17.2]: https://github.com/monero-rs/monero-rs/compare/v0.17.1...v0.17.2
[0.17.1]: https://github.com/monero-rs/monero-rs/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/monero-rs/monero-rs/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/monero-rs/monero-rs/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/monero-rs/monero-rs/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/monero-rs/monero-rs/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/monero-rs/monero-rs/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/monero-rs/monero-rs/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/monero-rs/monero-rs/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/monero-rs/monero-rs/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/monero-rs/monero-rs/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/monero-rs/monero-rs/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/monero-rs/monero-rs/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/monero-rs/monero-rs/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/monero-rs/monero-rs/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/monero-rs/monero-rs/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/monero-rs/monero-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/monero-rs/monero-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/monero-rs/monero-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/monero-rs/monero-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/monero-rs/monero-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/monero-rs/monero-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/monero-rs/monero-rs/releases/tag/v0.1.0
