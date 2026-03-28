//! Release-mode soundness tests for the Plonky3 STARK backend.
//!
//! In debug builds `p3_uni_stark::prove` calls `check_constraints` internally,
//! which panics before returning a proof.  That means a bad witness is caught
//! by the prover itself — an acceptable but weak guarantee (it only holds while
//! debug assertions are enabled).
//!
//! In RELEASE builds the prover skips `check_constraints`.  A dishonest prover
//! CAN call `prove()` with a constraint-violating trace and get bytes back.
//! These tests verify that `verify()` then rejects those bytes — i.e., the
//! FRI polynomial-commitment layer actually enforces the constraints rather
//! than just the pre-flight check.
//!
//! Run with:
//!   cargo test --release --test plonky3_soundness_release -- --nocapture

#![cfg(not(debug_assertions))]

use zkdb_plonky3::backend::Plonky3Backend;
use zkdb_plonky3::backend::traits::ProvingBackend;
use zkdb_plonky3::backend::plonky3::Plonky3CircuitHandle;
use zkdb_plonky3::circuit::witness::{ColumnTrace, WitnessTrace};
use zkdb_plonky3::field::FieldElement;
use zkdb_plonky3::types::{QueryId, SnapshotId};

fn fe(v: u64) -> FieldElement { FieldElement(v) }
fn fes(vs: &[u64]) -> Vec<FieldElement> { vs.iter().map(|&v| fe(v)).collect() }

// ─────────────────────────────────────────────────────────────────────────────
// Filter soundness (release mode)
// ─────────────────────────────────────────────────────────────────────────────

/// In release mode a dishonest prover can call `prove()` with a witness that
/// sets `selector = 1` for a row whose value does NOT satisfy the filter
/// predicate.  The circuit constraint `selector * (value − filter_val) = 0`
/// will be non-zero in that row, so the FRI verifier MUST reject the proof.
///
/// Constraint chain:
///   selector=1, value=100, filter_val=200
///   → selector * (value − filter_val) = 1 * (100 − 200) = −100 ≠ 0
///   → constraint polynomial ≠ 0 on domain
///   → OodEvaluationMismatch at verifier
#[tokio::test]
async fn test_plonky3_filter_constraint_rejects_bad_witness() {
    let backend = Plonky3Backend::new();
    let handle  = Plonky3CircuitHandle { num_cols: 4, num_rows: 8 };

    let vals = [100u64, 500, 200, 800, 50];

    // ── Bad witness: row 0 (value=100) selected despite filter_val=200 ────────
    let mut bad = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    bad.columns    = vec![ColumnTrace::new("val", fes(&vals))];
    bad.selected   = vec![true, false, false, false, false]; // row 0: val=100, sel=1
    bad.filter_op  = 1;   // equality
    bad.filter_val = 200;

    // In release mode prove() does NOT panic — it returns bytes.
    let result = backend.prove(&handle, &bad).await;
    match result {
        Err(e) => {
            // Acceptable: the backend detected the invalid witness
            println!("filter soundness (release): prove rejected bad witness: {e:?}");
        }
        Ok(artifact) => {
            // Proof was generated; verify MUST reject it
            let verify_result = backend.verify(&artifact).await;
            println!(
                "filter soundness (release): verify result = {:?}",
                verify_result.as_ref().err()
            );
            assert!(
                verify_result.is_err(),
                "FAIL: bad filter witness produced a verifiable proof — \
                 the constraint is NOT enforced by the FRI layer"
            );
            println!("filter soundness (release): ✓ FRI verifier correctly rejected the proof");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Join key-equality soundness (release mode)
// ─────────────────────────────────────────────────────────────────────────────

/// A dishonest prover sets `selector = 1` for a row where `left_key ≠ right_key`.
/// The circuit constraint `selector * (left_key − right_key) = 0` is violated.
/// The FRI verifier must reject the proof.
///
/// Constraint chain:
///   selector=1, left_key=1, right_key=2
///   → 1 * (1 − 2) = −1 ≠ 0
///   → OodEvaluationMismatch
#[tokio::test]
async fn test_plonky3_join_constraint_rejects_bad_witness() {
    let backend = Plonky3Backend::new();
    let handle  = Plonky3CircuitHandle { num_cols: 5, num_rows: 8 };

    // Row 0: left_key=1, right_key=2 — MISMATCH but selector=1
    let mut bad = WitnessTrace::new(QueryId::new(), SnapshotId::new());
    bad.columns = vec![
        ColumnTrace::new("left_key",  fes(&[1, 2, 3])),
        ColumnTrace::new("right_key", fes(&[2, 2, 3])), // row 0 mismatched
        ColumnTrace::new("left_val",  fes(&[10, 20, 30])),
    ];
    bad.selected = vec![true; 3];

    let result = backend.prove(&handle, &bad).await;
    match result {
        Err(e) => {
            println!("join soundness (release): prove rejected bad witness: {e:?}");
        }
        Ok(artifact) => {
            let verify_result = backend.verify(&artifact).await;
            println!(
                "join soundness (release): verify result = {:?}",
                verify_result.as_ref().err()
            );
            assert!(
                verify_result.is_err(),
                "FAIL: bad join witness produced a verifiable proof — \
                 key-equality constraint is NOT enforced by the FRI layer"
            );
            println!("join soundness (release): ✓ FRI verifier correctly rejected the proof");
        }
    }
}
