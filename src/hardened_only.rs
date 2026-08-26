//! Generic framework for hardened-only key derivation.
//!
//! Defined in [ZIP 32: Hardened-only key derivation][hkd].
//!
//! Any usage of the types in this module needs to have a corresponding ZIP (except via
//! [`arbitrary::SecretKey`] but that is [NOT RECOMMENDED for new protocols][adhockd]).
//!
//! [hkd]: https://zips.z.cash/zip-0032#specification-hardened-only-key-derivation
//! [adhockd]: https://zips.z.cash/zip-0032#specification-ad-hoc-key-derivation-deprecated
//! [`arbitrary::SecretKey`]: crate::arbitrary::SecretKey

use core::{fmt, marker::PhantomData};

use blake2b_simd::Params as Blake2bParams;
use subtle::{Choice, ConstantTimeEq};
use zcash_spec::{PrfExpand, VariableLengthSlice};

use crate::{ChainCode, ChildIndex};

pub(crate) type HardenedOnlyCkdDomain =
    PrfExpand<([u8; 32], [u8; 4], [u8; 1], VariableLengthSlice)>;

/// The context in which hardened-only key derivation is instantiated.
pub trait Context {
    /// A 16-byte domain separator used during master key generation.
    ///
    /// It SHOULD be disjoint from other domain separators used with BLAKE2b in Zcash
    /// protocols.
    const MKG_DOMAIN: [u8; 16];
    /// The `PrfExpand` domain used during child key derivation.
    const CKD_DOMAIN: HardenedOnlyCkdDomain;
}

/// An arbitrary or registered extended secret key.
///
/// Defined in [ZIP 32: Hardened-only key derivation][hkd].
///
/// If the `zeroize` feature is enabled, the key material is zeroized on drop.
///
/// [hkd]: https://zips.z.cash/zip-0032#specification-hardened-only-key-derivation
#[derive(Clone)]
pub struct HardenedOnlyKey<C: Context> {
    sk: [u8; 32],
    chain_code: ChainCode,
    _context: PhantomData<C>,
}

impl<C: Context> fmt::Debug for HardenedOnlyKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted: do not print secret key material.
        f.debug_struct("HardenedOnlyKey").finish_non_exhaustive()
    }
}

#[cfg(feature = "zeroize")]
impl<C: Context> zeroize::Zeroize for HardenedOnlyKey<C> {
    fn zeroize(&mut self) {
        self.sk.zeroize();
        self.chain_code.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: Context> zeroize::ZeroizeOnDrop for HardenedOnlyKey<C> {}

#[cfg(feature = "zeroize")]
impl<C: Context> Drop for HardenedOnlyKey<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl<C: Context> ConstantTimeEq for HardenedOnlyKey<C> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.chain_code.ct_eq(&rhs.chain_code) & self.sk.ct_eq(&rhs.sk)
    }
}

#[allow(non_snake_case)]
impl<C: Context> HardenedOnlyKey<C> {
    /// Constructs a hardened-only key from its parts.
    ///
    /// Crate-internal because we want this to only be used within specific contexts.
    pub(crate) fn from_parts(sk: [u8; 32], chain_code: ChainCode) -> Self {
        Self {
            sk,
            chain_code,
            _context: PhantomData,
        }
    }

    /// Exposes the parts of this key.
    pub fn parts(&self) -> (&[u8; 32], &ChainCode) {
        (&self.sk, &self.chain_code)
    }

    /// Decomposes this key into its parts.
    ///
    /// The caller takes responsibility for the returned key material; `self` is
    /// zeroized on drop if the `zeroize` feature is enabled.
    pub(crate) fn into_parts(self) -> ([u8; 32], ChainCode) {
        // Copy the parts out rather than moving them, so that `self` can still be
        // dropped (and zeroized) normally.
        (self.sk, self.chain_code)
    }

    /// Generates the master key of a hardened-only extended secret key.
    ///
    /// Defined in [ZIP 32: Hardened-only master key generation][mkgh].
    ///
    /// [mkgh]: https://zips.z.cash/zip-0032#hardened-only-master-key-generation
    pub fn master(ikm: &[&[u8]]) -> Self {
        // I := BLAKE2b-512(Context.MKGDomain, IKM)
        let mut I: [u8; 64] = {
            let mut I = Blake2bParams::new()
                .hash_length(64)
                .personal(&C::MKG_DOMAIN)
                .to_state();
            for input in ikm {
                I.update(input);
            }
            I.finalize().as_bytes().try_into().expect("64-byte output")
        };
        let key = Self::from_bytes(&I);
        zeroize_prf_output(&mut I);
        key
    }

    /// Derives a child key from a parent key at a given index and empty tag.
    ///
    /// This is a convenience function equivalent to
    /// `self.derive_child_with_tag(index, &[])`.
    pub fn derive_child(&self, index: ChildIndex) -> Self {
        self.derive_child_with_tag(index, &[])
    }

    /// Derives a child key from a parent key at a given index and (possibly empty)
    /// tag.
    ///
    /// Defined in [ZIP 32: Hardened-only child key derivation][ckdh].
    ///
    /// [ckdh]: https://zips.z.cash/zip-0032#hardened-only-child-key-derivation
    pub fn derive_child_with_tag(&self, index: ChildIndex, tag: &[u8]) -> Self {
        let mut I = self.ckdh_internal(index, 0, tag);
        let key = Self::from_bytes(&I);
        zeroize_prf_output(&mut I);
        key
    }

    /// Defined in [ZIP 32: Hardened-only child key derivation][ckdh].
    ///
    /// This returns `I` rather than `(I_L, I_R)` so that we don't have
    /// to re-concatenate the pieces, e.g. when using it in
    /// [`crate::registered::SecretKey::derive_child_cryptovalue`].
    ///
    /// The returned array contains secret key material; callers are responsible for
    /// zeroizing it once they are done with it.
    ///
    /// [ckdh]: https://zips.z.cash/zip-0032#hardened-only-child-key-derivation
    pub(crate) fn ckdh_internal(&self, index: ChildIndex, lead: u8, tag: &[u8]) -> [u8; 64] {
        // One of these depending on lead and tag:
        // - I := PRF^Expand(c_par, [Context.CKDDomain] || sk_par || I2LEOSP(i))
        // - I := PRF^Expand(c_par, [Context.CKDDomain] || sk_par || I2LEOSP(i) || [lead] || tag)
        C::CKD_DOMAIN.with(
            self.chain_code.as_bytes(),
            &self.sk,
            &index.index().to_le_bytes(),
            &[lead],
            tag,
        )
    }

    fn from_bytes(I: &[u8; 64]) -> Self {
        let (I_L, I_R) = I.split_at(32);

        // I_L is used as the spending key sk.
        let sk = I_L.try_into().unwrap();

        // I_R is used as the chain code c.
        let chain_code = ChainCode::new(I_R.try_into().unwrap());

        Self {
            sk,
            chain_code,
            _context: PhantomData,
        }
    }
}

/// Zeroizes a 64-byte PRF output that was used as intermediate key material.
///
/// This is a no-op unless the `zeroize` feature is enabled.
#[inline]
#[allow(unused_variables)]
pub(crate) fn zeroize_prf_output(i: &mut [u8; 64]) {
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(i);
}

#[cfg(all(test, feature = "zeroize"))]
mod tests {
    use zeroize::Zeroize;

    use zcash_spec::PrfExpand;

    use super::{Context, HardenedOnlyCkdDomain, HardenedOnlyKey};
    use crate::{ChainCode, ChildIndex};

    struct TestContext;

    impl Context for TestContext {
        const MKG_DOMAIN: [u8; 16] = *b"ZIP32TestContext";
        const CKD_DOMAIN: HardenedOnlyCkdDomain = PrfExpand::REGISTERED_ZIP32_CHILD;
    }

    #[test]
    fn zeroize_clears_key_material() {
        let mut key = HardenedOnlyKey::<TestContext>::master(&[&[0xab; 32]])
            .derive_child(ChildIndex::hardened(1));
        {
            let (sk, c) = key.parts();
            assert_ne!(sk, &[0; 32]);
            assert_ne!(c, &ChainCode::new([0; 32]));
        }

        key.zeroize();
        let (sk, c) = key.parts();
        assert_eq!(sk, &[0; 32]);
        assert_eq!(c, &ChainCode::new([0; 32]));
    }

    #[test]
    fn debug_is_redacted() {
        let key = HardenedOnlyKey::<TestContext>::master(&[&[0xab; 32]]);
        assert_eq!(alloc::format!("{:?}", key), "HardenedOnlyKey { .. }");
    }
}
