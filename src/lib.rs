//! Implementation of [ZIP 32] for hierarchical deterministic key management.
//!
//! [ZIP 32]: https://zips.z.cash/zip-0032

use memuse::{self, DynamicUsage};
use subtle::{Choice, ConditionallySelectable};

pub mod fingerprint;

/// A type-safe wrapper for account identifiers.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(u32);

memuse::impl_no_dynamic_usage!(AccountId);

impl From<u32> for AccountId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<AccountId> for u32 {
    fn from(id: AccountId) -> Self {
        id.0
    }
}

impl From<AccountId> for ChildIndex {
    fn from(id: AccountId) -> Self {
        // Account IDs are always hardened in derivation paths.
        ChildIndex::hardened(id.0)
    }
}

impl ConditionallySelectable for AccountId {
    fn conditional_select(a0: &Self, a1: &Self, c: Choice) -> Self {
        AccountId(u32::conditional_select(&a0.0, &a1.0, c))
    }
}

// ZIP 32 structures

/// A child index for a derived key.
///
/// Only hardened derivation is supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildIndex(u32);

impl ChildIndex {
    /// Parses the given ZIP 32 child index.
    ///
    /// Returns `None` if the hardened bit is not set.
    pub fn from_index(i: u32) -> Option<Self> {
        if i >= (1 << 31) {
            Some(ChildIndex(i))
        } else {
            None
        }
    }

    /// Constructs a hardened `ChildIndex` from the given value.
    ///
    /// # Panics
    ///
    /// Panics if `value >= (1 << 31)`.
    pub const fn hardened(value: u32) -> Self {
        assert!(value < (1 << 31));
        Self(value + (1 << 31))
    }

    /// Returns the index as a 32-bit integer, including the hardened bit.
    pub fn index(&self) -> u32 {
        self.0
    }
}

/// A value that is needed, in addition to a spending key, in order to derive descendant
/// keys and addresses of that key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainCode([u8; 32]);

impl ChainCode {
    /// Constructs a `ChainCode` from the given array.
    pub fn new(c: [u8; 32]) -> Self {
        Self(c)
    }

    /// Returns the byte representation of the chain code, as required for
    /// [ZIP 32](https://zips.z.cash/zip-0032) encoding.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversifierIndex(pub [u8; 11]);

impl Default for DiversifierIndex {
    fn default() -> Self {
        DiversifierIndex::new()
    }
}

impl From<u32> for DiversifierIndex {
    fn from(i: u32) -> Self {
        u64::from(i).into()
    }
}

impl From<u64> for DiversifierIndex {
    fn from(i: u64) -> Self {
        let mut result = DiversifierIndex([0; 11]);
        result.0[..8].copy_from_slice(&i.to_le_bytes());
        result
    }
}

impl TryFrom<DiversifierIndex> for u32 {
    type Error = std::num::TryFromIntError;

    fn try_from(di: DiversifierIndex) -> Result<u32, Self::Error> {
        let mut u128_bytes = [0u8; 16];
        u128_bytes[0..11].copy_from_slice(&di.0[..]);
        u128::from_le_bytes(u128_bytes).try_into()
    }
}

impl DiversifierIndex {
    pub fn new() -> Self {
        DiversifierIndex([0; 11])
    }

    pub fn increment(&mut self) -> Result<(), ()> {
        for k in 0..11 {
            self.0[k] = self.0[k].wrapping_add(1);
            if self.0[k] != 0 {
                // No overflow
                return Ok(());
            }
        }
        // Overflow
        Err(())
    }
}

/// The scope of a viewing key or address.
///
/// A "scope" narrows the visibility or usage to a level below "full".
///
/// Consistent usage of `Scope` enables the user to provide consistent views over a wallet
/// to other people. For example, a user can give an external [SaplingIvk] to a merchant
/// terminal, enabling it to only detect "real" transactions from customers and not
/// internal transactions from the wallet.
///
/// [SaplingIvk]: crate::sapling::SaplingIvk
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// A scope used for wallet-external operations, namely deriving addresses to give to
    /// other users in order to receive funds.
    External,
    /// A scope used for wallet-internal operations, such as creating change notes,
    /// auto-shielding, and note management.
    Internal,
}

memuse::impl_no_dynamic_usage!(Scope);

#[cfg(test)]
mod tests {
    use super::DiversifierIndex;
    use assert_matches::assert_matches;

    #[test]
    fn diversifier_index_to_u32() {
        let two = DiversifierIndex([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(u32::try_from(two), Ok(2));

        let max_u32 = DiversifierIndex([
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(u32::try_from(max_u32), Ok(u32::MAX));

        let too_big = DiversifierIndex([
            0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_matches!(u32::try_from(too_big), Err(_));
    }
}
