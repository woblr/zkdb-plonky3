//! Integration test: full Plonky3 prove-verify pipeline.
//!
//! Exercises:
//!   1. Dataset creation + row ingestion
//!   2. Snapshot commit + activation
//!   3. Query parsing + proof plan generation
//!   4. Witness generation
//!   5. Plonky3 prove (BabyBear FRI-STARK)
//!   6. Plonky3 verify
//!
//! Run with:
//!   cargo test test_plonky3_full_pipeline -- --nocapture

use std::sync::Arc;
use std::time::Instant;

use zkdb_plonky3::backend::Plonky3Backend;
use zkdb_plonky3::benchmarks::runner::BenchmarkRunner;
use zkdb_plonky3::benchmarks::types::{BackendKind, BenchmarkScenario};

/// End-to-end Plonky3 pipeline: ingest → snapshot → query → prove → verify.
///
/// Dataset: 8 synthetic transaction rows.
/// Query: `SELECT COUNT(*) FROM benchmark_transactions`
///
/// Note: the zkDB prototype requires the filter column to match the aggregate
/// column (cross-column filter+aggregate not yet supported).  COUNT(*) is the
/// simplest query that exercises the full pipeline without hitting that limit.
#[tokio::test]
async fn test_plonky3_full_pipeline() {
    let backend = Arc::new(Plonky3Backend::new());
    let runner = BenchmarkRunner::in_memory(backend);

    let scenario = BenchmarkScenario::new(
        "plonky3_count_all",
        "SELECT COUNT(*) FROM benchmark_transactions",
        8, // 8 rows — fast, still covers the prove path
    )
    .with_backend(BackendKind::Plonky3);

    println!("\n[plonky3] running prove-verify pipeline ...");
    let t0 = Instant::now();
    let result = runner.run(&scenario).await;
    let total_ms = t0.elapsed().as_millis();

    // ── diagnostics ──────────────────────────────────────────────────────────
    println!("[plonky3] success          : {}", result.success);
    if let Some(ref e) = result.error {
        println!("[plonky3] error            : {e}");
    }
    println!(
        "[plonky3] dataset gen      : {} µs",
        result.metrics.dataset_generation_us
    );
    println!(
        "[plonky3] ingestion        : {} µs",
        result.metrics.ingestion_us
    );
    println!(
        "[plonky3] snapshot         : {} µs",
        result.metrics.snapshot_creation_us + result.metrics.snapshot_activation_us
    );
    println!(
        "[plonky3] query planning   : {} µs",
        result.metrics.query_planning_us
    );
    println!(
        "[plonky3] prove time       : {} µs  ({:.1} ms)",
        result.metrics.proof_generation_us,
        result.metrics.proof_generation_us as f64 / 1000.0
    );
    println!(
        "[plonky3] verify time      : {} µs  ({:.1} ms)",
        result.metrics.verification_us,
        result.metrics.verification_us as f64 / 1000.0
    );
    println!(
        "[plonky3] proof size       : {} bytes  ({:.2} KB)",
        result.metrics.proof_size_bytes,
        result.metrics.proof_size_bytes as f64 / 1024.0
    );
    println!("[plonky3] wall-clock total : {total_ms} ms");

    // ── assertions ───────────────────────────────────────────────────────────
    assert!(result.success, "pipeline must succeed: {:?}", result.error);
    assert!(
        result.metrics.proof_size_bytes > 0,
        "proof must be non-empty"
    );
    assert!(result.proof_id.is_some(), "proof_id must be set");
}
