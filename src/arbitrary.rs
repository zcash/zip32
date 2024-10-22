//! Arbitrary key derivation.
//!
//! In some contexts there is a need for deriving arbitrary keys with the same derivation
//! path as existing key material (for example, deriving an arbitrary account-level key),
//! without the need for ecosystem-wide coordination. The following instantiation of the
//! [hardened key generation framework] may be used for this purpose.
//!
//! Defined in [ZIP32: Arbitrary key derivation][arbkd].
//!
//! [hardened key generation framework]: crate::hardened_only
//! [arbkd]: https://zips.z.cash/zip-0032#specification-arbitrary-key-derivation

use zcash_spec::PrfExpand;

use crate::{
    hardened_only::{Context, HardenedOnlyKey},
    ChainCode, ChildIndex,
};

struct Arbitrary;

impl Context for Arbitrary {
    const MKG_DOMAIN: [u8; 16] = *b"ZcashArbitraryKD";
    const CKD_DOMAIN: PrfExpand<([u8; 32], [u8; 4])> = PrfExpand::ARBITRARY_ZIP32_CHILD;
}

/// An arbitrary extended secret key.
///
/// Defined in [ZIP32: Arbitrary key derivation][arbkd].
///
/// [arbkd]: https://zips.z.cash/zip-0032#specification-arbitrary-key-derivation
pub struct SecretKey {
    inner: HardenedOnlyKey<Arbitrary>,
}

impl SecretKey {
    /// Derives an arbitrary key at the given path from the given seed.
    ///
    /// `context_string` is an identifier for the context in which this key will be used.
    /// It must be globally unique.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the context string is empty or longer than 252 bytes.
    /// - the seed is shorter than 32 bytes or longer than 252 bytes.
    pub fn from_path(context_string: &[u8], seed: &[u8], path: &[ChildIndex]) -> Self {
        let mut xsk = Self::master(context_string, seed);
        for i in path {
            xsk = xsk.derive_child(*i);
        }
        xsk
    }

    /// Generates the master key of an Arbitrary extended secret key.
    ///
    /// Defined in [ZIP32: Arbitrary master key generation][mkgarb].
    ///
    /// [mkgarb]: https://zips.z.cash/zip-0032#arbitrary-master-key-generation
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the context string is empty or longer than 252 bytes.
    /// - the seed is shorter than 32 bytes or longer than 252 bytes.
    fn master(context_string: &[u8], seed: &[u8]) -> Self {
        let context_len =
            u8::try_from(context_string.len()).expect("context string should be at most 252 bytes");
        assert!((1..=252).contains(&context_len));

        let seed_len = u8::try_from(seed.len()).expect("seed should be at most 252 bytes");
        assert!((32..=252).contains(&seed_len));

        let ikm = &[&[context_len], context_string, &[seed_len], seed];

        Self {
            inner: HardenedOnlyKey::master(ikm),
        }
    }

    /// Derives a child key from a parent key at a given index.
    ///
    /// Defined in [ZIP32: Arbitrary-only child key derivation][ckdarb].
    ///
    /// [ckdarb]: https://zips.z.cash/zip-0032#arbitrary-child-key-derivation
    fn derive_child(&self, index: ChildIndex) -> Self {
        Self {
            inner: self.inner.derive_child(index),
        }
    }

    /// Returns the key material for this arbitrary key.
    pub fn data(&self) -> &[u8; 32] {
        self.inner.parts().0
    }

    /// Returns the chain code for this arbitrary key.
    pub fn chain_code(&self) -> &ChainCode {
        self.inner.parts().1
    }

    /// Concatenates the key data and chain code to obtain a full-width key.
    ///
    /// This may be used when a context requires a 64-byte key instead of a 32-byte key
    /// (for example, to avoid an entropy bottleneck in its particular subsequent
    /// operations).
    ///
    /// Child keys MUST NOT be derived from any key on which this method is called. For
    /// the current API, this means that [`SecretKey::from_path`] MUST NOT be called with
    /// a `path` for which this key's path is a prefix.
    pub fn into_full_width_key(self) -> [u8; 64] {
        let (sk, c) = self.inner.into_parts();
        // Re-concatenate the key parts.
        let mut key = [0; 64];
        key[..32].copy_from_slice(&sk);
        key[32..].copy_from_slice(&c.0);
        key
    }
}
