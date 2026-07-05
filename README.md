# sha2rs

A minimal, from-scratch implementation of the SHA-224 hash function in Rust — no crypto crates, just the algorithm as specified in FIPS 180-4.

## What it does

Hashes a hardcoded input (`"mukul"`) and prints the resulting 28-byte (224-bit) digest as hex.

## Run

```sh
cargo run
```

## Why

Written as an exercise to understand SHA-2 internals: message padding, the message schedule expansion, and the compression function (choose, majority, and the Σ/σ rotation functions).

## Status

Educational implementation. Currently hashes a single fixed input — not yet a general-purpose hashing library (no CLI args, file input, or incremental/streaming API).
