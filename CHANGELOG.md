# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `zip32::registered` module, implementing hardened-only key derivation for
  an application protocol specified in a ZIP.
- `zip32::ChildIndex::PRIVATE_USE`

### Deprecated
- `zip32::arbitrary::SecretKey::into_full_width_key`. This API is
  cryptographically unsafe because it depends on a restriction that cannot
  be enforced. Use `zip32::registered::full_width_from_path` instead.

## [0.1.3] - 2024-12-13

### Fixed
- Disabled default features of dependencies to fix no-std support.

## [0.1.2] - 2024-10-22

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
