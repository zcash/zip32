# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zip32::arbitrary` module, implementing hardened-only "arbitrary" key
  derivation that needs no ecosystem-wide coordination.
- `zip32::hardened_only` module, providing a generic hardened-only key
  derivation framework (initially used for Orchard and `zip32::arbitrary`).
- `impl {PartialOrd, Ord, Hash}` for `zip32::DiversifierIndex`

## [0.1.1] - 2024-03-14

### Added
- `impl {Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash}` for 
  `zip32::fingerprint::SeedFingerprint`
- `zip32::fingerprint::SeedFingerprint::from_bytes`

## [0.1.0] - 2023-12-06
Initial release.
