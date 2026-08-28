# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zeroize` feature flag (enabled by default), which enables the `zeroize`
  dependency (without its default features, so `no_std` is preserved) and:
  - `impl zeroize::Zeroize for zip32::ChainCode`
  - `impl zeroize::{Zeroize, ZeroizeOnDrop} for zip32::hardened_only::HardenedOnlyKey`
  - `impl zeroize::{Zeroize, ZeroizeOnDrop} for zip32::registered::SecretKey`
  - `impl zeroize::{Zeroize, ZeroizeOnDrop} for zip32::arbitrary::SecretKey`
  When enabled, `HardenedOnlyKey` (and therefore both `SecretKey` types) are
  zeroized on drop, including every intermediate key produced while deriving
  a path, and the intermediate 64-byte PRF outputs used during derivation.
- `impl Debug for zip32::registered::SecretKey` and
  `impl Debug for zip32::arbitrary::SecretKey` (redacted).

### Changed
- `impl Debug for zip32::hardened_only::HardenedOnlyKey` no longer prints the
  secret key material; it now renders as `HardenedOnlyKey { .. }`.

## [0.2.1] - 2025-09-17

### Added
- `zip32::AccountId::const_from_u32`
- `zip32::fingerprint`:
  - `impl {FromStr, Display} for SeedFingerprint`, providing the Bech32m
    encoding of a ZIP 32 seed fingerprint.
  - `ParseError`

## [0.2.0] - 2025-02-20

### Added
- `zip32::registered` module, implementing hardened-only key derivation for
  an application protocol specified in a ZIP.
- `zip32::ChildIndex::PRIVATE_USE`
- `zip32::hardened_only::HardenedOnlyKey::{from_parts, derive_child_with_tag}`

### Changed
- The type of `zip32::hardened_only::Context::CKD_DOMAIN` has changed, in
  order to support child derivation with tags.

### Deprecated
- `zip32::arbitrary::SecretKey::into_full_width_key`. This API is
  cryptographically unsafe because it depends on a restriction that cannot
  be enforced. Use `zip32::registered::cryptovalue_from_subpath` instead.

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
