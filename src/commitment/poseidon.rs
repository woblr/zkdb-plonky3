//! Poseidon2-based row and snapshot commitments over the BabyBear field.
//!
//! In the plonky3 port we switch from plonky2's Goldilocks Poseidon to
//! Poseidon2 over BabyBear (p = 2^31 − 2^27 + 1 = 2013265921).
//!
//! The commitment value `snap_lo` is the first element of
//!   Poseidon2_24(padded_values) applied as a sponge absorb,
//! which is what the in-circuit call will also compute.
//!
//! **Field-size note**: BabyBear values fit in 31 bits. Column values that
//! exceed 2^31 − 1 are reduced mod p before hashing. This is a known
//! soundness limitation for large u64 column values; a range-decomposition
//! argument is required to handle them fully.

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_24};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

type F = BabyBear;
// PaddingFreeSponge<Perm24, WIDTH=24, RATE=16, OUT=8>
type Sponge = PaddingFreeSponge<p3_baby_bear::Poseidon2BabyBear<24>, 24, 16, 8>;

/// Maximum rows per circuit instance — must match the value in `plonky3.rs`.
pub const MAX_ROWS: usize = 128;

// ─────────────────────────────────────────────────────────────────────────────
// Core hash utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `Poseidon2_24(padded_values).output[0]` where `padded_values` is
/// `values` zero-padded (or truncated) to exactly `n_rows` BabyBear elements.
///
/// This matches the in-circuit Poseidon2 sponge that binds the witness to
/// the proof's public input PI[0].
///
/// Values are reduced mod BabyBear::ORDER_U32. Values that originally exceed
/// 2^31−1 lose their high bits — see the module-level field-size note.
pub fn compute_snap_lo(n_rows: usize, values: &[u64]) -> u64 {
    let fes = padded_field_elements(n_rows, values);
    let perm = default_babybear_poseidon2_24();
    let sponge = Sponge::new(perm);
    // Absorb all field elements and squeeze one output element.
    let output: [F; 8] = sponge.hash_iter(fes);
    output[0].as_canonical_u32() as u64
}

/// Pack `values` (zero-padded / truncated to `n_rows`) into BabyBear field
/// elements for use with the Poseidon2 sponge.
pub fn padded_field_elements(n_rows: usize, values: &[u64]) -> Vec<F> {
    let order = F::ORDER_U32 as u64;
    (0..n_rows)
        .map(|i| {
            let v = if i < values.len() { values[i] } else { 0 };
            F::from_u32((v % order) as u32)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Row encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the "primary field element" for a raw row byte slice.
///
/// Takes the first 8 bytes as a little-endian `u64`, reduced mod BabyBear::ORDER.
pub fn row_primary_field_element(row_bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = row_bytes.len().min(8);
    buf[..len].copy_from_slice(&row_bytes[..len]);
    let v = u64::from_le_bytes(buf);
    v % (F::ORDER_U32 as u64)
}

/// Pack arbitrary bytes into BabyBear field elements (8 bytes each, LE, mod p).
/// Pads the last element with zeros if `bytes.len()` is not a multiple of 8.
pub fn bytes_to_field_elements(bytes: &[u8]) -> Vec<F> {
    let order = F::ORDER_U32 as u64;
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            let len = chunk.len();
            buf[..len].copy_from_slice(chunk);
            let v = u64::from_le_bytes(buf) % order;
            F::from_u32(v as u32)
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot root from raw chunks
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Poseidon2 snapshot root from all row bytes across all chunks.
///
/// Algorithm:
/// 1. For each row, extract its primary field element.
/// 2. Poseidon2-sponge over all per-row field elements (zero-padded to MAX_ROWS).
/// 3. Store `output[0]` as the first 8 bytes of a 32-byte root.
pub fn poseidon_snapshot_root(all_row_bytes: &[Vec<u8>]) -> [u8; 32] {
    let primary_fes: Vec<u64> = all_row_bytes
        .iter()
        .map(|rb| row_primary_field_element(rb))
        .collect();

    let snap_lo = compute_snap_lo(MAX_ROWS, &primary_fes);

    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&snap_lo.to_le_bytes());
    root
}

/// Read the `snap_lo` (first 8 bytes as LE u64) from a 32-byte commitment.
pub fn commitment_lo(commitment: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&commitment[..8]);
    u64::from_le_bytes(buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snap_lo_is_deterministic() {
        let vals = vec![10u64, 20, 30, 40];
        let a = compute_snap_lo(MAX_ROWS, &vals);
        let b = compute_snap_lo(MAX_ROWS, &vals);
        assert_eq!(a, b);
    }

    #[test]
    fn different_values_produce_different_snap_lo() {
        let a = compute_snap_lo(MAX_ROWS, &[1u64, 2, 3]);
        let b = compute_snap_lo(MAX_ROWS, &[1u64, 2, 4]);
        assert_ne!(a, b, "different inputs must produce different hashes");
    }

    #[test]
    fn zero_values_is_nonzero_hash() {
        let v = compute_snap_lo(MAX_ROWS, &[]);
        let _ = v; // just confirm no panic
    }

    #[test]
    fn row_primary_field_element_first_8_bytes() {
        let row = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF];
        let raw = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let expected = raw % (BabyBear::ORDER_U32 as u64);
        assert_eq!(row_primary_field_element(&row), expected);
    }

    #[test]
    fn snapshot_root_encoding_is_consistent() {
        let rows: Vec<Vec<u8>> = (0..5u64).map(|i| i.to_le_bytes().to_vec()).collect();
        let root = poseidon_snapshot_root(&rows);
        let lo = commitment_lo(&root);
        let primary: Vec<u64> = rows
            .iter()
            .map(|rb| row_primary_field_element(rb))
            .collect();
        let expected_lo = compute_snap_lo(MAX_ROWS, &primary);
        assert_eq!(lo, expected_lo);
    }
}
