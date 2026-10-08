// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 256-bit integers for Base58 prefix ranges.
//!
//! Prefix validation runs once. The search itself compares 25-byte payloads.

use std::cmp::Ordering;

/// Little-endian limbs.
#[derive(Clone, Copy, Debug, Eq)]
pub(crate) struct U256([u64; 4]);

impl PartialEq for U256 {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0[3]
            .cmp(&other.0[3])
            .then(self.0[2].cmp(&other.0[2]))
            .then(self.0[1].cmp(&other.0[1]))
            .then(self.0[0].cmp(&other.0[0]))
    }
}

impl U256 {
    pub(crate) const ZERO: Self = Self([0, 0, 0, 0]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0]);

    /// `2^bit`. `bit` must be less than 256.
    pub(crate) fn pow2(bit: u32) -> Self {
        debug_assert!(bit < 256);
        let mut out = Self::ZERO;
        out.0[(bit / 64) as usize] = 1u64 << (bit % 64);
        out
    }

    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 {
            return None;
        }
        let mut be = [0u8; 32];
        be[32 - bytes.len()..].copy_from_slice(bytes);
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = (3 - index) * 8;
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&be[start..start + 8]);
            *limb = u64::from_be_bytes(wide);
        }
        Some(Self(limbs))
    }

    pub(crate) fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            let start = (3 - index) * 8;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// The low 25 bytes, when the value fits in 25 bytes.
    pub(crate) fn to_payload_bytes(self) -> Option<[u8; 25]> {
        let be = self.to_be_bytes();
        if be[..7] != [0; 7] {
            return None;
        }
        let mut out = [0u8; 25];
        out.copy_from_slice(&be[7..]);
        Some(out)
    }

    pub(crate) fn to_u64(self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    pub(crate) fn bit(self, index: u32) -> bool {
        ((self.0[(index / 64) as usize] >> (index % 64)) & 1) == 1
    }

    fn with_bit(self, index: u32) -> Self {
        let mut out = self;
        out.0[(index / 64) as usize] |= 1u64 << (index % 64);
        out
    }

    pub(crate) fn checked_add(self, rhs: Self) -> Option<Self> {
        let (sum, overflow) = self.overflowing_add(rhs);
        if overflow {
            None
        } else {
            Some(sum)
        }
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        debug_assert!(self >= rhs);
        let mut borrow = 0u64;
        let mut out = [0u64; 4];
        for (index, limb) in out.iter_mut().enumerate() {
            let (difference, borrowed) = self.0[index].overflowing_sub(rhs.0[index]);
            let (difference, borrowed2) = difference.overflowing_sub(borrow);
            *limb = difference;
            borrow = u64::from(borrowed || borrowed2);
        }
        debug_assert!(borrow == 0);
        Self(out)
    }

    fn shl1(self) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (index, limb) in out.iter_mut().enumerate() {
            let next = self.0[index] >> 63;
            *limb = (self.0[index] << 1) | carry;
            carry = next;
        }
        (Self(out), carry != 0)
    }

    pub(crate) fn div_mod(self, divisor: Self) -> (Self, Self) {
        debug_assert!(divisor != Self::ZERO);
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for index in (0..256).rev() {
            let (shifted, overflow) = remainder.shl1();
            remainder = shifted;
            if self.bit(index) {
                remainder.0[0] |= 1;
            }
            // Values used here fit well below 2^255, so a shift of the
            // remainder cannot overflow. The assert catches a future caller
            // that violates that.
            debug_assert!(!overflow);
            if remainder >= divisor {
                remainder = remainder.sub(divisor);
                quotient = quotient.with_bit(index);
            }
        }
        (quotient, remainder)
    }

    /// Nearest integer of `self / divisor`. Half rounds away from zero.
    /// `None` when the quotient does not fit in a `u64`.
    pub(crate) fn div_round_u64(self, divisor: Self) -> Option<u64> {
        if divisor == Self::ZERO {
            return None;
        }
        let (quotient, remainder) = self.div_mod(divisor);
        let (twice, twice_overflow) = remainder.overflowing_add(remainder);
        let round_up = twice_overflow || twice >= divisor;
        let quotient = if round_up {
            quotient.checked_add(Self::ONE)?
        } else {
            quotient
        };
        quotient.to_u64()
    }

    /// Shift left by `bits`. `None` if the result does not fit in 256 bits.
    pub(crate) fn shl(self, bits: u32) -> Option<Self> {
        if bits >= 256 {
            return None;
        }
        let words = (bits / 64) as usize;
        let rem = bits % 64;
        if words > 0 {
            for limb in &self.0[4 - words..] {
                if *limb != 0 {
                    return None;
                }
            }
        }
        if rem != 0 && self.0[3 - words] >> (64 - rem) != 0 {
            return None;
        }
        let mut out = [0u64; 4];
        for (index, limb) in out.iter_mut().enumerate().skip(words) {
            let source = index - words;
            let mut value = self.0[source] << rem;
            if rem != 0 && source > 0 {
                value |= self.0[source - 1] >> (64 - rem);
            }
            *limb = value;
        }
        Some(Self(out))
    }

    fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut carry = 0u64;
        let mut out = [0u64; 4];
        for (index, limb) in out.iter_mut().enumerate() {
            let (sum, overflow) = self.0[index].overflowing_add(rhs.0[index]);
            let (sum, overflow2) = sum.overflowing_add(carry);
            *limb = sum;
            carry = u64::from(overflow || overflow2);
        }
        (Self(out), carry != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::U256;

    #[test]
    fn version_span_is_two_to_the_192() {
        let min = U256::from_be_bytes(&[0x1e]).unwrap().shl(192).unwrap();
        let max = min.checked_add(U256::pow2(192)).unwrap().sub(U256::ONE);
        assert_eq!(max.sub(min).checked_add(U256::ONE), Some(U256::pow2(192)));
        let payload = min.to_payload_bytes().unwrap();
        assert_eq!(payload[0], 0x1e);
        assert!(payload[1..].iter().all(|byte| *byte == 0));
    }
}
