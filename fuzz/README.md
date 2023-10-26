# Fuzzing monero-rs

See https://rust-fuzz.github.io/book/cargo-fuzz.html for more information on fuzzing with cargo-fuzz.
Install `cargo-fuzz` as per [installation instructions](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html).

**Note:** Fuzzing is not supported on Windows yet.

To get a list of fuzz targets, from a terminal in the project root, run

```
cargo fuzz list
```

To run a fuzz test, from a terminal in the project root, run

```
cargo +nightly fuzz run --release <fuzz_target_name>
```
