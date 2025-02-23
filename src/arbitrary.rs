//! Ad-hoc ("arbitrary") key derivation.
//!
//! For compatibility with existing deployments, we define a mechanism to generate
//! ad-hoc key trees for private use by applications, without ecosystem coordination,
//! using the [hardened key derivation framework].
//!
//! This used to be called "arbitrary key derivation" in ZIP 32, but that term caused
//! confusion as to the applicability of the mechanism and so has been renamed to
//! "ad-hoc key derivation". The module name is still `arbitrary` for compatibility.
//!
//! Since there is no guarantee of non-collision between different application protocols,
//! and no way to tie these key trees to well-defined specification or documentation
//! processes, use of this mechanism is NOT RECOMMENDED for new protocols.
//!
//! The keys derived by the functions in this module will be unrelated to any keys
//! derived by functions in the [`crate::registered`] module, even if the same context
//! string and seed are used.
//!
//! Defined in [ZIP 32: Ad-hoc key derivation (deprecated)][adhockd].
//!
//! [hardened key derivation framework]: crate::hardened_only
//! [adhockd]: https://zips.z.cash/zip-0032#specification-ad-hoc-key-derivation-deprecated

use zcash_spec::PrfExpand;

use crate::{
    hardened_only::{Context, HardenedOnlyCkdDomain, HardenedOnlyKey},
    ChainCode, ChildIndex,
};

use super::with_ikm;

struct Adhoc;

impl Context for Adhoc {
    const MKG_DOMAIN: [u8; 16] = *b"ZcashArbitraryKD";
    const CKD_DOMAIN: HardenedOnlyCkdDomain = PrfExpand::ADHOC_ZIP32_CHILD;
}

/// An ad-hoc extended secret key.
///
/// Defined in [ZIP 32: Ad-hoc key generation (deprecated)][adhockd].
///
/// [adhockd]: https://zips.z.cash/zip-0032#specification-ad-hoc-key-derivation-deprecated
pub struct SecretKey {
    inner: HardenedOnlyKey<Adhoc>,
}

impl SecretKey {
    /// Derives an ad-hoc key at the given path from the given seed.
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

    /// Generates the master key of an ad-hoc extended secret key.
    ///
    /// Defined in [ZIP 32: Ad-hoc master key generation (deprecated)][adhocmkg].
    ///
    /// [adhocmkg]: https://zips.z.cash/zip-0032#ad-hoc-master-key-generation-deprecated
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the context string is empty or longer than 252 bytes.
    /// - the seed is shorter than 32 bytes or longer than 252 bytes.
    fn master(context_string: &[u8], seed: &[u8]) -> Self {
        with_ikm(context_string, seed, |ikm| Self {
            inner: HardenedOnlyKey::master(ikm),
        })
    }

    /// Derives a child key from a parent key at a given index.
    ///
    /// Defined in [ZIP 32: Ad-hoc child key derivation (deprecated)][adhocckd].
    ///
    /// [adhocckd]: https://zips.z.cash/zip-0032#ad-hoc-child-key-derivation-deprecated
    fn derive_child(&self, index: ChildIndex) -> Self {
        Self {
            inner: self.inner.derive_child(index),
        }
    }

    /// Returns the key material for this key.
    pub fn data(&self) -> &[u8; 32] {
        self.inner.parts().0
    }

    /// Returns the chain code for this key.
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
    /// a `path` for which this key's path is a prefix. This API is cryptographically
    /// unsafe because there is no way to enforce that restriction.
    #[deprecated(
        since = "0.1.4",
        note = "Use [`zip32::registered::cryptovalue_from_subpath`] instead."
    )]
    pub fn into_full_width_key(self) -> [u8; 64] {
        let (sk, c) = self.inner.into_parts();
        // Re-concatenate the key parts.
        let mut key = [0; 64];
        key[..32].copy_from_slice(&sk);
        key[32..].copy_from_slice(&c.0);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::{with_ikm, ChildIndex, SecretKey};

    struct TestVector {
        context_string: &'static [u8],
        seed: [u8; 32],
        ikm: Option<&'static [u8]>,
        path: &'static [u32],
        sk: [u8; 32],
        c: [u8; 32],
    }

    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0032_arbitrary.py
    const TEST_VECTORS: &[TestVector] = &[
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: Some(&[
                0x12, 0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65,
                0x63, 0x74, 0x6f, 0x72, 0x73, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ]),
            path: &[],
            sk: [
                0xe9, 0xda, 0x88, 0x06, 0x40, 0x9d, 0xc3, 0xc3, 0xeb, 0xd1, 0xfc, 0x2a, 0x71, 0xc8,
                0x79, 0xc1, 0x3d, 0xd7, 0xaa, 0x93, 0xed, 0xe8, 0x03, 0xbf, 0x1a, 0x83, 0x41, 0x4b,
                0x9d, 0x3b, 0x15, 0x8a,
            ],
            c: [
                0x65, 0xa7, 0x48, 0xf2, 0x90, 0x5f, 0x7a, 0x8a, 0xab, 0x9f, 0x3d, 0x02, 0xf1, 0xb2,
                0x6c, 0x3d, 0x65, 0xc8, 0x29, 0x94, 0xce, 0x59, 0xa0, 0x86, 0xd4, 0xc6, 0x51, 0xd8,
                0xa8, 0x1c, 0xec, 0x51,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483649],
            sk: [
                0xe8, 0x40, 0x9a, 0xaa, 0x83, 0x2c, 0xc2, 0x37, 0x8f, 0x2b, 0xad, 0xeb, 0x77, 0x15,
                0x05, 0x62, 0x15, 0x37, 0x42, 0xfe, 0xe8, 0x76, 0xdc, 0xf4, 0x78, 0x3a, 0x6c, 0xcd,
                0x11, 0x9d, 0xa6, 0x6a,
            ],
            c: [
                0xcc, 0x08, 0x49, 0x22, 0xa0, 0xea, 0xd2, 0xda, 0x53, 0x38, 0xbd, 0x82, 0x20, 0x0a,
                0x19, 0x46, 0xbc, 0x85, 0x85, 0xb8, 0xd9, 0xee, 0x41, 0x6d, 0xf6, 0xa0, 0x9a, 0x71,
                0xab, 0x0e, 0x5b, 0x58,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483649, 2147483650],
            sk: [
                0x46, 0x4f, 0x90, 0xa3, 0x64, 0xcf, 0xf8, 0x05, 0xfe, 0xe9, 0x3a, 0x85, 0xb7, 0x2f,
                0x48, 0x94, 0xce, 0x4e, 0x13, 0x58, 0xdc, 0xdc, 0x1e, 0x61, 0xa3, 0xd4, 0x30, 0x30,
                0x1c, 0x60, 0x91, 0x0e,
            ],
            c: [
                0xf9, 0xd2, 0x54, 0x4a, 0x55, 0x28, 0xae, 0x6b, 0xd9, 0xf0, 0x36, 0xf4, 0x2f, 0x9f,
                0x05, 0xd8, 0x3d, 0xff, 0x50, 0x7a, 0xeb, 0x2a, 0x81, 0x41, 0xaf, 0x11, 0xd9, 0xf1,
                0x67, 0xe2, 0x21, 0xae,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483649, 2147483650, 2147483651],
            sk: [
                0xfc, 0x4b, 0x6e, 0x93, 0xb0, 0xe4, 0x2f, 0x7a, 0x76, 0x2c, 0xa0, 0xc6, 0x52, 0x2c,
                0xcd, 0x10, 0x45, 0xca, 0xb5, 0x06, 0xb3, 0x72, 0x45, 0x2a, 0xf7, 0x30, 0x6c, 0x87,
                0x38, 0x9a, 0xb6, 0x2c,
            ],
            c: [
                0xe8, 0x9b, 0xf2, 0xed, 0x73, 0xf5, 0xe0, 0x88, 0x75, 0x42, 0xe3, 0x67, 0x93, 0xfa,
                0xc8, 0x2c, 0x50, 0x8a, 0xb5, 0xd9, 0x91, 0x98, 0x57, 0x82, 0x27, 0xb2, 0x41, 0xfb,
                0xac, 0x19, 0x84, 0x29,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483680],
            sk: [
                0xc4, 0x30, 0xc4, 0xde, 0xfd, 0x03, 0xd7, 0x57, 0x8b, 0x2b, 0xb0, 0x9e, 0x58, 0x13,
                0x5c, 0xdd, 0x1d, 0x7b, 0x7c, 0x97, 0x5f, 0x01, 0xa8, 0x90, 0x84, 0x7e, 0xe0, 0xb5,
                0xc4, 0x68, 0xbc, 0x98,
            ],
            c: [
                0x0f, 0x47, 0x37, 0x89, 0xfe, 0x7d, 0x55, 0x85, 0xb7, 0x9a, 0xd5, 0xf7, 0xe0, 0xa4,
                0x69, 0xd9, 0xa3, 0x01, 0x46, 0x64, 0x77, 0x64, 0x48, 0x51, 0x50, 0xdb, 0x78, 0xd7,
                0x20, 0x9d, 0xcb, 0x30,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483680, 2147483781],
            sk: [
                0x43, 0xe5, 0x48, 0x46, 0x79, 0xfd, 0xfa, 0x0f, 0x61, 0x76, 0xae, 0x86, 0x79, 0x5d,
                0x0d, 0x44, 0xc4, 0x0e, 0x14, 0x9e, 0xf4, 0xba, 0x1b, 0x0e, 0x2e, 0xbd, 0x88, 0x3c,
                0x71, 0xf4, 0x91, 0x87,
            ],
            c: [
                0xdb, 0x42, 0xc3, 0xb7, 0x25, 0xf3, 0x24, 0x59, 0xb2, 0xcf, 0x82, 0x15, 0x41, 0x8b,
                0x8e, 0x8f, 0x8e, 0x7b, 0x1b, 0x3f, 0x4a, 0xba, 0x2f, 0x5b, 0x5e, 0x81, 0x29, 0xe6,
                0xf0, 0x57, 0x57, 0x84,
            ],
        },
        TestVector {
            context_string: &[
                0x5a, 0x63, 0x61, 0x73, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
                0x74, 0x6f, 0x72, 0x73,
            ],
            seed: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            ikm: None,
            path: &[2147483680, 2147483781, 2147483648],
            sk: [
                0xbf, 0x60, 0x07, 0x83, 0x62, 0xa0, 0x92, 0x34, 0xfc, 0xbc, 0x6b, 0xf6, 0xc8, 0xa8,
                0x7b, 0xde, 0x9f, 0xc7, 0x37, 0x76, 0xbf, 0x93, 0xf3, 0x7a, 0xdb, 0xcc, 0x43, 0x9a,
                0x85, 0x57, 0x4a, 0x9a,
            ],
            c: [
                0x2b, 0x65, 0x7e, 0x08, 0xf6, 0x7a, 0x57, 0x0c, 0x53, 0xb9, 0xed, 0x30, 0x61, 0x1e,
                0x6a, 0x2f, 0x82, 0x26, 0x62, 0xb4, 0x88, 0x7a, 0x8c, 0xfb, 0x46, 0x9e, 0x9d, 0x0d,
                0x98, 0x17, 0x01, 0x1a,
            ],
        },
    ];

    #[test]
    fn test_vectors() {
        let context_string = b"Zcash test vectors";

        for tv in TEST_VECTORS {
            assert_eq!(tv.context_string, context_string);

            let path = tv
                .path
                .iter()
                .map(|i| ChildIndex::from_index(*i).expect("hardened"))
                .collect::<alloc::vec::Vec<_>>();

            // The derived master key should be identical to the key at the empty path.
            if let Some(mut tv_ikm) = tv.ikm {
                with_ikm(tv.context_string, &tv.seed, |ikm| {
                    for part in ikm {
                        assert_eq!(*part, &tv_ikm[..part.len()]);
                        tv_ikm = &tv_ikm[part.len()..];
                    }
                });

                let sk = SecretKey::master(context_string, &tv.seed);
                assert_eq!((sk.data(), sk.chain_code().as_bytes()), (&tv.sk, &tv.c));
            }

            let sk = SecretKey::from_path(tv.context_string, &tv.seed, &path);
            assert_eq!(sk.data(), &tv.sk);
            assert_eq!(sk.chain_code().as_bytes(), &tv.c);
        }
    }
}
