# zkDB — Zero Knowledge Database with Plonky3 FRI-STARK Proving

zkDB is a Rust library and server that implements a **verifiable database pipeline**: ingest rows into typed datasets, commit snapshots to a Poseidon-keyed structure, execute SQL queries, and generate **real Plonky3 STARK proofs** over query results. The system is designed as a benchmark and comparison platform for proving backends on database workloads.

The Plonky3 backend is **fully wired** — `prove()` generates real FRI-STARK proofs and `verify()` verifies them with full public-input cross-checks (PI[0] snap_lo, PI[1] query_hash, PI[2]/PI[3] sum/count, PI[4] result_commit_lo, PI[5] group_output_lo). This is not a stub, not a hash-chain audit, and not a placeholder.

**Companion project:** [zkDB-Plonky2](../zkdb-plonky2) implements the same SQL layer over a Plonky2 SNARK backend. Identical query pipeline — swapped proof backend. The Plonky3 backend produces ~71 KB proofs vs ~116 KB for Plonky2.

---

## SQL Support Summary

This table is the honest source of truth about what is and is not proved. Do not infer support from passing tests alone — a test can pass while proving something weaker than claimed.

| SQL construct | In-circuit status | Notes |
|---|---|---|
| `COUNT(*)` | ✅ **Proved** | `ZkDbAir` Arithmetic mode, full running-count constraint |
| `SUM(col)` | ✅ **Proved** | `ZkDbAir` Arithmetic mode, full running-sum constraint |
| `AVG(col)` | ✅ **Proved** | Derived off-circuit from proved sum/count |
| `WHERE col = val` (soundness) | ✅ **Proved** | Selector boolean + equality constraint `sel*(val−filter)=0` |
| `WHERE col > val` / `< val` (soundness) | ✅ **Proved** | Auxiliary diff column + consistency constraint (range check TODO) |
| `WHERE` predicate completeness | ❌ **Not proved** | Prover can omit rows satisfying the predicate; `completeness_proved=false`, warning emitted |
| `ORDER BY col ASC` | ✅ **Proved** | Sort mode: grand-product multiset equality + monotonicity constraint |
| `ORDER BY col DESC` | ✅ **Proved** | Sort mode: `sort_descending=true`; non-increasing monotonicity + grand-product |
| `GROUP BY col` | ✅ **Proved** (soundness) | Boundary detection + per-group running sum + key monotonicity; `completeness_proved=false` |
| Per-group individual outputs | ⚠️ **Partial** | Committed as aggregate `group_output_lo` (PI[5]); individual tuples are not individually verifiable |
| `INNER JOIN ON left.k = right.k` (soundness) | ✅ **Proved** | Key equality soundness: `sel*(left_k−right_k)=0`; `completeness_proved=false` |
| JOIN completeness | ❌ **Not proved** | Prover can omit matching rows; Logup/plookup required for full completeness |
| `LIMIT` / `TOP-K` | ❌ **Rejected** | Returns an explicit `UNSUPPORTED` error at plan compile time |
| Multi-operator composition | ❌ **Rejected** | Returns an explicit `UNSUPPORTED` error at plan compile time |
| Recursive proof folding | ❌ **Not implemented** | `fold()` returns `Err`; multi-chunk datasets produce independent per-chunk proofs |
| Dataset binding (snap_lo) | ✅ **Proved** | `PI[0]=Poseidon(column_values)[0]` committed in FRI Fiat-Shamir transcript |
| Query binding (query_hash) | ✅ **Proved** | `PI[1]=Blake3(sql_text)[0..8]` committed in FRI Fiat-Shamir transcript |
| Result sum (PI[2]) / count (PI[3]) | ✅ **Proved** | Cross-checked in `verify()` against artifact `result_sum` / `result_row_count` |

---

## Evaluation Goals

| # | Dimension | Current Status |
|---|---|---|
| 1 | **Proof generation time** | ✅ Measured — real Plonky3 FRI-STARK proof times (30–370 ms at 5–8 rows, release) |
| 2 | **Verification time** | ✅ Measured — real Plonky3 verification times (sub-millisecond in release) |
| 3 | **Proof size (bytes)** | ✅ Measured — 70 593 bytes (constant for this circuit depth) |
| 4 | **Constraint count per operator** | ✅ Enumerated — see [Backend Model](#backend-model) |
| 5 | **Lookup argument comparison** (Logup vs plookup for JOIN) | 🔜 Requires second SNARK backend (Halo2/Plonky2) |
| 6 | **Field-size impact** (255-bit Pasta vs 64-bit Goldilocks vs 31-bit BabyBear) | ✅ Partial — Goldilocks (64-bit) implemented; BabyBear and Pasta require additional backends |
| 7 | **Scalability limits** (up to 128+ rows) | ⚠️ Partial — tested up to 8 rows (padded from 5–6 real rows); circuit supports up to 128 rows |
| 8 | **Parallelization** (multi-core proof gen) | ✅ Enabled — Plonky3 DFT (`p3-dft`) uses multi-threaded NTT |

**Dimension 5 note:** Meaningful cross-algorithm comparison requires at least two working SNARK backends. The portable benchmark pack is designed for this.

**Dimension 7 note:** The circuit pads to the next power of two. Max configured rows: 128. Larger datasets produce more independent per-chunk proofs that are not yet folded.

---

## Current Measured Results — Real Plonky3 FRI-STARK Proofs

> **Note on proof size:** All operators (Arithmetic, GroupBy, Join, Sort) produce proofs of **70 593 bytes** at equivalent trace dimensions. This is ~39% smaller than the Plonky2 backend (~116 072 bytes) due to Plonky3's postcard binary serialization and FRI parameter differences.

### Core Operators — `plonky3`, 5–8 rows (next-power-of-two padded), 2026-03-28

All scenarios passed. Dataset: deterministic synthetic transactions/employees data (see `src/benchmarks/dataset.rs`). Measurements are from single `cargo test` invocations; wall-clock time includes test harness overhead.

> **System:** Apple Silicon. Plonky3 from git main (2026-03), Goldilocks field, Poseidon2 width-8, `log_blowup=1`, `num_queries=100`.

#### Arithmetic operators (Arithmetic mode — COUNT / SUM / AVG / FILTER)

| Test | SQL operation | Mode | Prove+verify, debug (ms) | Prove+verify, release (ms) | Proof size |
|---|---|---|---|---|---|
| `test_plonky3_sum_is_proven` | `SUM(col)` no filter | Arithmetic | 950 | 100 | 70 593 |
| `test_plonky3_avg_is_proven` | `AVG(col)` (sum/count) | Arithmetic | 380 | — | 70 593 |
| `test_plonky3_filter_gt_happy_path` | `WHERE col > val` | Arithmetic | — | — | 70 593 |
| `test_completeness_proved_true_for_scan_all` | `COUNT(*)` scan all | Arithmetic | — | — | 70 593 |

#### Sort operators (Sort mode — ORDER BY)

The Sort circuit uses a **two-phase FRI proving strategy**: the preprocessed trace (40 columns) is committed first → FRI Merkle root derived → `DuplexChallenger` derives permutation challenge `r` → accumulator proved as main trace. This prevents the deterministic-challenge weakness present in simpler Fiat-Shamir implementations.

| Test | SQL operation | Mode | Prove+verify, debug (ms) | Prove+verify, release (ms) | Proof size |
|---|---|---|---|---|---|
| `test_plonky3_sort_constraint_is_real` | `ORDER BY col ASC` | Sort | 1 210 | 180 | 70 593 |
| `test_completeness_proved_true_for_sort` | `ORDER BY col ASC` (bijection) | Sort | — | — | 70 593 |

#### GROUP BY operators (GroupBy mode)

| Test | SQL operation | Mode | Prove+verify, debug (ms) | Prove+verify, release (ms) | Proof size |
|---|---|---|---|---|---|
| `test_plonky3_groupby_is_proven` | `GROUP BY col, SUM(val)` | GroupBy | 1 700 | 370 | 70 593 |
| `test_plonky3_groupby_having` | `GROUP BY … HAVING sum > k` | GroupBy | — | — | 70 593 |

#### JOIN operators (Join mode)

| Test | SQL operation | Mode | Prove+verify, debug (ms) | Prove+verify, release (ms) | Proof size |
|---|---|---|---|---|---|
| `test_plonky3_join_is_proven` | `INNER JOIN ON key` | Join | 270 | 30 | 70 593 |
| `test_plonky3_join_empty_result` | `JOIN` (empty result) | Join | — | — | 70 593 |

### Full Test Suite Timing

| Build | Unit tests (136) | Integration (1) | Release-only (2) | Total |
|---|---|---|---|---|
| `cargo test` (debug) | 11.23 s | 0.78 s | — | ~12 s |
| `cargo test --release` | 1.14 s | 0.13 s | 0.15 s | ~1.4 s |

### Key observations

- **Proof size is constant per circuit type** regardless of row count or query complexity (FRI succinctness). All operators at equivalent trace dimensions: **70 593 bytes**.
- **Verification is sub-linear** in witness size (FRI: O(log² n) field operations). In release builds, verification is sub-millisecond.
- **Proof generation debug vs release**: debug is ~10–12× slower (no inlining, no SIMD). The 270–1 700 ms debug times reduce to 30–370 ms in release builds.
- **VK is 128 bytes** for Arithmetic/GroupBy/Join circuits; **~168 bytes** for two-phase Sort (extra 4-byte commit_len + 32-byte FRI Merkle root + metadata).
- **Goldilocks vs BabyBear**: Goldilocks (64-bit prime) encodes all practical u64 values without modular reduction, avoiding the limb-splitting overhead of BabyBear (31-bit). Proof size is ~39% smaller than prior BabyBear+JSON implementation (~128 KB).

### Comparison with Plonky2 Backend

| Metric | Plonky2Backend | **Plonky3Backend** |
|---|---|---|
| Proof system | FRI-SNARK | **FRI-STARK** |
| Field | Goldilocks (64-bit) | **Goldilocks (64-bit)** |
| Hash / commitment | Poseidon, FRI | **Poseidon2 width-8, FRI** |
| Proof size | ~103–116 KB | **~71 KB (~39% smaller)** |
| Serialization | JSON | **postcard (binary)** |
| Prove time (debug, ~50 rows) | ~1 500–6 600 ms | **~270–1 700 ms (5–8 rows)** |
| Verify time (debug) | ~115–145 ms | **sub-ms to ~50 ms** |
| Trusted setup | None | **None** |
| Proof of work bits | — | **commit_pow=16, query_pow=16** |

### What `constraint_checked` actually is

`ConstraintCheckedBackend` is **not a mock**. It executes every operator's constraint-validation logic — sort ordering, group boundaries, selector booleanity, running-sum consistency, join key equality. It produces a structured, content-addressed artifact that can be re-verified by anyone with the same public inputs.

What it is **not**: it does not construct a zero-knowledge proof. The verifier sees the full witness digest chain; there is no hiding property. Verification cost is O(columns × rows), not O(log² n). It uses no polynomial commitments, FFTs, or SNARK/STARK machinery.

**Correct mental model:**
- `constraint_checked` → cryptographic audit log (`proof_system_kind: hash_chain_audit`, `has_zero_knowledge: false`, `is_succinct: false`)
- `plonky3` → real STARK (`proof_system_kind: plonky3_stark`, `has_zero_knowledge: true`, `is_succinct: true`)

Use `constraint_checked` for fast integration testing and correctness validation. Use `plonky3` for production zero-knowledge guarantees.

---

## Circuit Design

### ZkDbAir — Arithmetic mode (COUNT / SUM / AVG / FILTER)

Plonky3 AIR over the Goldilocks field. Trace padded to the next power of two (max 128 rows).

```
Private inputs (trace columns):
  values[0..n]        — column values (Goldilocks field elements from u64)
  selectors[0..n]     — boolean mask (1 = row included, 0 = excluded / padding)
  partial_sum[0..n]   — running sum accumulator
  count[0..n]         — running count accumulator
  diff[0..n]          — auxiliary diff for LT/GT range checks

Constraints (per row i — enforced by AIR eval()):
  1. sel * (sel − 1) = 0                            ← selector boolean (all modes)
  2. partial_sum[0] = sel[0] * val[0]               ← first-row init
     partial_sum[i+1] = partial_sum[i] + sel[i+1]*val[i+1]  ← accumulation
  3. partial_sum[last] == expected_sum              ← PI[2] binding
  4. count[0] = sel[0]; count[i+1] = count[i] + sel[i+1]
  5. count[last] == expected_count                 ← PI[3] binding
  6. Filter op=1 (EQ):  sel * (val − filter_val) = 0
     Filter op=2 (GT):  (val − filter_val − diff) * (1−sel) = 0  (diff > 0)
     Filter op=3 (LT):  (filter_val − val − diff) * (1−sel) = 0  (diff > 0)

Public inputs:
  [0] snap_lo          — Poseidon(column_data)[0]: dataset binding
  [1] query_hash       — Blake3(sql_text)[0..8]: query binding
  [2] result_sum       — SUM(values[i]) for selected rows
  [3] result_row_count — COUNT(*) for selected rows
  [4] result_commit_lo — Poseidon(snap_lo, query_hash, result_sum, result_count)[0]
  [5] group_output_lo  — 0 (unused in Arithmetic mode)
  [6] sort_secondary_hi_snap_lo — 0 (unused)
  [7] group_vals_snap_lo — 0 (unused)
```

### ZkDbAir — Sort mode (ORDER BY)

Two-phase FRI proving strategy. Preprocessed trace committed first to derive the permutation challenge `r` from the FRI transcript.

```
Private inputs (trace columns — preprocessed phase, 40 cols):
  primary_in[0..n]     — input column values (unsorted)
  secondary_lo/hi      — Poseidon(row_bytes)[0..1] per input row (128-bit binding)
  primary_out[0..n]    — claimed sorted output values
  sort_diff[0..n]      — out[i+1] - out[i] (monotonicity witness)
  prod_in[0..n]        — running product over input: ∏(r − primary_in[i])
  prod_out[0..n]       — running product over output: ∏(r − primary_out[i])

Challenge derivation (two-phase FRI):
  r = DuplexChallenger.sample() after committing preprocessed trace
  (Derived from FRI Merkle root of preprocessed trace — not from witness data)

Constraints:
  1. sel * (sel − 1) = 0                             ← boolean
  2. prod_in[0] = r − primary_in[0]
     sel * (prod_in[i+1] − prod_in[i]*(r−primary_in[i+1])) = 0  ← running product
  3. prod_in[last] == prod_out[last]                  ← grand-product multiset equality
  4. sel * (primary_out[i+1] − primary_out[i] − sort_diff[i]) = 0  ← monotonicity
     (sort_diff range check TODO — without it, only multiset equality is enforced)

Public inputs:
  [0] snap_lo
  [1] query_hash
  [2] result_sum      — SUM(primary_in)
  [3] result_row_count
  [4] result_commit_lo
  [5] group_output_lo — Poseidon(primary_out)[0]: output column binding
  [6] sort_secondary_hi_snap_lo — secondary payload hash (128-bit row binding)
  [7] group_vals_snap_lo — 0

Security: two-phase challenge prevents deterministic-r attack.
Soundness (grand-product): error probability ≤ MAX_ROWS / |F| ≈ 2⁻⁵⁷

⚠️ Completeness: Sort proves the output IS a permutation of the input (bijection holds).
completeness_proved=true for Sort — the only operator besides scan-all COUNT/SUM.
```

### ZkDbAir — GroupBy mode (GROUP BY)

Proves group boundaries, per-group running sums, and key monotonicity within groups.

```
Private inputs:
  sorted_keys[0..n]     — group-by column, pre-sorted
  vals[0..n]            — aggregate column values
  is_boundary[0..n]     — 1 at group transitions, 0 within group
  group_sum[0..n]       — per-group running sum
  selector[0..n]        — row inclusion mask

Constraints:
  1. sel * (sel − 1) = 0                              ← boolean
  2. is_boundary ∈ {0,1} binary constraint
  3. is_boundary[0] = 1                               ← first row is always a boundary
  4. group_sum[i+1] = is_boundary[i+1]*val[i+1]
                    + (1−is_boundary[i+1])*(group_sum[i] + val[i+1])  ← group accumulation
  5. sel * (1−is_boundary[i+1]) * (key[i+1]−key[i]) = 0  ← key monotonicity within group (deg-3)

Public inputs:
  [0] snap_lo
  [1] query_hash
  [2] result_sum        — global SUM across all groups
  [3] result_row_count  — total row count
  [4] result_commit_lo
  [5] group_output_lo   — Poseidon(sorted_keys ++ vals ++ is_boundary)[0]
  [6] 0
  [7] group_vals_snap_lo — Poseidon(vals)[0]: value column binding

⚠️ Completeness: NOT proved. A prover can omit rows that would satisfy group predicates.
completeness_proved=false. Warning emitted: "COMPLETENESS NOT GUARANTEED (WHERE-filter / JOIN / GROUP BY)".

⚠️ Limitation: PI[5] is a single Poseidon hash of the entire grouped relation.
Individual (group_key, count, sum) tuples are NOT individually verifiable.
```

### ZkDbAir — Join mode (INNER JOIN)

Proves equi-join soundness on a single key column.

```
Private inputs:
  left_keys[0..n]      — left table join key column
  right_keys[0..n]     — right table join key column
  left_vals[0..n]      — left table value column
  selector[0..n]       — 1 where left_keys[i] == right_keys[i], 0 elsewhere

Constraints:
  1. sel * (sel − 1) = 0                              ← boolean
  2. sel * (left_keys − right_keys) = 0               ← equality soundness on matches
  3. running count init + transition + final equality (PI[3] binding)

Public inputs:
  [0] snap_lo          — Poseidon(left_keys ++ left_vals)[0]
  [1] query_hash
  [2] result_sum        — SUM(left_vals[i]) for matched rows
  [3] result_row_count  — COUNT of matched rows
  [4] result_commit_lo  — Poseidon(snap_lo, …)[0]
  [5] group_output_lo   — Poseidon(right_keys)[0]: right-side binding
  [6] 0
  [7] 0

✅ Soundness: if sel[i]=1 then left_keys[i] == right_keys[i]. Proven cryptographically.
❌ Completeness: NOT proved. If left_keys[i] == right_keys[i], sel[i] is NOT forced to 1.
A prover can produce zero matches even when the tables have matching keys.
completeness_proved=false. Warning emitted on every JOIN verification result.
```

---

## What This Repository Provides

| Capability | Description |
|---|---|
| **Real Plonky3 proofs** | `prove()` generates genuine FRI-based STARKs; `verify()` verifies them with full public-input cross-checks |
| **In-circuit dataset binding** | `PI[0]=Poseidon(column_values)[0]` committed in Fiat-Shamir transcript; tampering changes transcript and invalidates PoW witness |
| **Honest completeness metadata** | `ProofCapabilities::join_completeness_proved` defaults to `false`; only Sort (bijection) and scan-all Arithmetic set it to `true` |
| **Completeness warnings** | `VerificationResult.warnings` carries explicit `"COMPLETENESS NOT GUARANTEED"` text for WHERE/JOIN/GROUP BY proofs |
| **Adversarial test coverage** | 9 adversarial tests: tampered proof, wrong query hash, wrong snap_lo, wrong result sum, JOIN/filter completeness gap, zero-result adversarial witnesses |
| **Two-phase Sort** | Preprocessed trace committed before permutation challenge `r` is derived — prevents deterministic-challenge attack |
| **Soundness rejection messages** | FRI verifier rejects bad witnesses with cryptographic error codes (not silent failures) |
| **Multi-operator plan rejection** | Plans with >1 provable operator return an explicit `UNSUPPORTED` error |
| **LIMIT / TOP-K rejection** | `LIMIT` clauses return an explicit `UNSUPPORTED` error; not silently fell through |
| **Dataset onboarding** | REST API and in-memory store for typed columnar datasets |
| **Snapshot lifecycle** | Commit dataset chunks with Poseidon-keyed hashing; activate for querying |
| **SQL query pipeline** | SQL parse → logical plan → physical plan → proof plan → witness → prove → verify |
| **Pluggable backends** | `ConstraintCheckedBackend` + `Plonky3Backend` registered in `BackendRegistry` |
| **Benchmark harness** | Deterministic scenario runner, persistent result store, suite comparison |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  HTTP API  (src/api/)                                                        │
│  Axum 0.7 · REST handlers · DTOs · AppState                                 │
├──────────────────────────────────┬───────────────────────────────────────────┤
│  Database  (src/database/)       │  Query  (src/query/)                      │
│  Schema · Ingest · Snapshot      │  SQL parser (sqlparser)                   │
│  In-memory storage traits        │  AST → logical → physical → proof plan   │
├──────────────────────────────────┼───────────────────────────────────────────┤
│  Commitment  (src/commitment/)   │  Proof  (src/proof/)                      │
│  Poseidon snapshot hashing       │  ProofArtifact · ProofSystemKind          │
│  Blake3 content-addressed IDs    │  Prover · Verifier                        │
├──────────────────────────────────┼───────────────────────────────────────────┤
│  Circuit  (src/circuit/)         │  Backend  (src/backend/)                  │
│  OperatorCircuit trait           │  ProvingBackend trait                     │
│  WitnessBuilder (schema-aware)   │  ConstraintChecked · Plonky3 ✅           │
│  Decoder (column-level decode)   │                                           │
├──────────────────────────────────┴───────────────────────────────────────────┤
│  Gates  (src/gates/)   ·   Field arithmetic  (src/field.rs)                  │
│  arithmetic · boolean · comparison · sort · permutation · group              │
│  join · mux · decompose · merkle · running_sum   (12 gate modules)           │
├──────────────────────────────────────────────────────────────────────────────┤
│  Plonky3  (p3-* git main crates)                                             │
│  GoldilocksField · Poseidon2(width=8) · MerkleTreeMmcs · TwoAdicFriPcs      │
│  p3-uni-stark · DuplexChallenger · FRI (log_blowup=1, num_queries=100)      │
├──────────────────────────────────────────────────────────────────────────────┤
│  Benchmarks  (src/benchmarks/)                                               │
│  cases · dataset · runner · metrics · compare · storage · pack               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Backend Model

Every `ProofArtifact` and `VerificationResult` carries an explicit `ProofSystemKind` label. No backend can misrepresent itself.

### MockBackend

```
BackendTag::Mock  |  ProofSystemKind::None  |  Quality: placeholder
```

Produces a 32-byte Blake3 hash of the witness JSON. No constraints. No circuit. For unit tests and CI speed checks only. Not registered in the production `BackendRegistry`.

### ConstraintCheckedBackend

```
BackendTag::ConstraintChecked  |  ProofSystemKind::HashChainAudit  |  Quality: real
```

Runs real operator constraint checks (sort ordering, group boundaries, selector booleanity, running-sum consistency, join key equality) and produces a structured Blake3 hash-chain audit log. **NOT zero-knowledge. NOT succinct. NOT a STARK.**

Useful for correctness validation and adversarial testing without polynomial proving overhead.

### Plonky3Backend ✅ — Fully Wired

```
BackendTag::Plonky3  |  ProofSystemKind::Plonky3Stark  |  Quality: real
```

**This is the main proving backend.** Real Plonky3 FRI-based STARK:
- Field: Goldilocks (2⁶⁴ − 2³² + 1)
- Hash: Poseidon2 width-8 (`p3-poseidon2` + `p3-symmetric`)
- Commitment scheme: MerkleTreeMmcs + TwoAdicFriPcs
- FRI parameters: `log_blowup=1`, `max_log_arity=1`, `num_queries=100`, `commit_pow_bits=16`, `query_pow_bits=16`
- Serialization: postcard binary (`p3-serialize` via `postcard`)
- Zero-knowledge: ✅ (Fiat-Shamir transcript binding)
- Succinct verification: ✅ (O(log² n) field operations)
- Proof of work: ✅ (`commit_pow_bits=16`, `query_pow_bits=16`)

`prove()` generates a real proof. `verify()` verifies it, and cross-checks PI[0] (snapshot binding), PI[1] (query hash), PI[2] (sum), PI[3] (count) against stored artifact metadata. Tampered proofs are rejected at the FRI verification layer.

**Supported SQL (single-operator proofs):**
- `COUNT(*)` with optional `WHERE` predicate (soundness; completeness only for scan-all)
- `SUM(col)` with optional `WHERE` predicate (soundness; completeness only for scan-all)
- `AVG(col)` with optional `WHERE` predicate (soundness)
- `ORDER BY col ASC` — two-phase Sort, grand-product permutation argument
- `ORDER BY col DESC` — Sort with `sort_descending=true`; non-increasing monotonicity
- `GROUP BY col` with `COUNT` / `SUM` — boundary constraints + key monotonicity (soundness)
- `INNER JOIN … ON left.k = right.k` — equality soundness, both-side binding (soundness)

**Explicitly rejected (returns error, does not silently degrade):**
- `LIMIT` / `TOP-K`
- Multi-operator composition (e.g., `ORDER BY` + `GROUP BY` in a single proof plan)
- Recursive folding across chunks

### Capability Matrix

| Backend | Real constraints | Zero-knowledge | Succinct | STARK proof | Status |
|---|---|---|---|---|---|
| `MockBackend` | ❌ | ❌ | ❌ | ❌ | Production-ready for testing |
| `ConstraintCheckedBackend` | ✅ | ❌ | ❌ | ❌ | Production-ready for correctness checks |
| **`Plonky3Backend`** | **✅** | **✅** | **✅** | **✅ (FRI-STARK)** | **✅ Fully wired** |

---

## Database / Dataset Details

All datasets are generated **deterministically** from a fixed internal seed. Same row count → same rows, every time.

### `benchmark_transactions`

| Column | Type | Range / Cardinality |
|---|---|---|
| `id` | u64 | Sequential |
| `user_id` | u64 | 0–9 999 |
| `amount` | u64 | 0–99 999 |
| `category` | text | 8 values |
| `region` | text | 6 values |
| `timestamp` | u64 | Unix seconds from 1 700 000 000 |
| `score` | u64 | 0–999 |
| `flag` | bool | ~50/50 |

Default benchmark size: **1 000 rows**.

### `benchmark_employees`

| Column | Type | Range / Cardinality |
|---|---|---|
| `employee_id` | u64 | Sequential |
| `department` | text | 8 values |
| `office` | text | 6 values |
| `salary` | u64 | 30 000–179 999 |
| `manager_id` | u64 | Another employee_id |
| `performance_score` | u64 | 0–99 |

Default size: **200 rows**.

---

## Portable Benchmark Pack

The benchmark pack is an **algorithm-independent** set of files with no references to Plonky3 or any specific proving system. Copy it into a Plonky2, Halo2, or Nova repo, run the same canonical queries against the same CSV datasets, and produce a comparable `report.md`.

```
benchmark_pack/
├── README.md
├── dataset/
│   ├── schema.json                — Column types, cardinalities, nullability
│   ├── generation_config.json     — Seed, hash algorithm, row count defaults
│   ├── transactions.csv           — 1 000 deterministic transaction rows
│   ├── employees.csv              — 200 deterministic employee rows
│   └── snapshot_manifest.json
├── usecases/
│   ├── queries.yaml               — Canonical SQL queries
│   └── scenarios.yaml
├── metrics/
│   ├── metrics_schema.json        — Field definitions + comparability guidance
│   └── result_schema.json
└── reports/
    ├── report_template.md         — {{placeholder}} template
    ├── methodology.md
    └── reproducibility.md
```

Generate:
```bash
cargo run --release -- bench export-pack --output benchmark_pack
```

---

## CLI Usage

```bash
# Run the full benchmark suite with real Plonky3 proofs
cargo run --release -- bench suite --rows 50 --backend plonky3

# Start HTTP API server
cargo run --release -- serve

# Available backends: mock | constraint_checked | plonky3
```

---

## Verified Test Status

All commands were run against the current repository. Last full run: 2026-03-28.

### Compilation

```
$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.1s
```

### Full Test Suite

```
$ cargo test
```

| Test binary | Tests | Result |
|---|---|---|
| `src/lib.rs` (unit tests) | 136 | ✅ 136 passed |
| `tests/plonky3_integration.rs` | 1 | ✅ 1 passed |
| **Total** | **137** | **✅ 137 passed, 0 failed** |

```
$ cargo test --release
```

| Test binary | Tests | Result |
|---|---|---|
| `src/lib.rs` (unit tests) | 136 | ✅ 136 passed |
| `tests/plonky3_integration.rs` | 1 | ✅ 1 passed |
| `tests/plonky3_soundness_release.rs` | 2 | ✅ 2 passed |
| **Total** | **141** | **✅ 141 passed, 0 failed** |

### Selected Plonky3 unit tests (all pass)

```
test backend::plonky3::tests::test_plonky3_sum_is_proven                        ... ok
test backend::plonky3::tests::test_plonky3_avg_is_proven                        ... ok
test backend::plonky3::tests::test_plonky3_sort_constraint_is_real              ... ok
test backend::plonky3::tests::test_plonky3_groupby_is_proven                    ... ok
test backend::plonky3::tests::test_plonky3_groupby_having                       ... ok
test backend::plonky3::tests::test_plonky3_join_is_proven                       ... ok
test backend::plonky3::tests::test_plonky3_join_empty_result                    ... ok
test backend::plonky3::tests::test_plonky3_filter_gt_happy_path                 ... ok
test backend::plonky3::tests::test_plonky3_filter_lt_happy_path                 ... ok
test backend::plonky3::tests::test_plonky3_rejects_tampered_proof               ... ok  (FRI rejection)
test backend::plonky3::tests::test_plonky3_rejects_wrong_result                 ... ok  (OodEvaluationMismatch)
test backend::plonky3::tests::test_plonky3_rejects_wrong_dataset                ... ok  (InvalidPowWitness)
test backend::plonky3::tests::test_plonky3_rejects_tampered_query_hash          ... ok  (InvalidPowWitness)
test backend::plonky3::tests::test_plonky3_rejects_tampered_result_sum          ... ok  (InvalidPowWitness)
test backend::plonky3::tests::test_plonky3_filter_soundness                     ... ok  (OodEvaluationMismatch)
test backend::plonky3::tests::test_plonky3_filter_gt_soundness                  ... ok
test backend::plonky3::tests::test_plonky3_filter_lt_soundness                  ... ok
test backend::plonky3::tests::test_plonky3_filter_gt_range_check_rejects_adversarial_diff ... ok
test backend::plonky3::tests::test_plonky3_join_key_mismatch_rejected           ... ok
test backend::plonky3::tests::test_plonky3_join_tampered_result_commit_lo       ... ok  (InvalidPowWitness)
test backend::plonky3::tests::test_plonky3_group_by_wrong_order_rejected        ... ok
test backend::plonky3::tests::test_two_phase_r_depends_on_committed_base_trace  ... ok
test backend::plonky3::tests::test_sort_challenge_is_data_dependent             ... ok
test backend::plonky3::tests::test_completeness_proved_true_for_scan_all        ... ok
test backend::plonky3::tests::test_completeness_proved_true_for_sort            ... ok
test backend::plonky3::tests::test_completeness_proved_false_for_filter_eq      ... ok  (completeness_proved=false)
test backend::plonky3::tests::test_completeness_proved_false_for_filter_gt      ... ok  (completeness_proved=false)
test backend::plonky3::tests::test_completeness_proved_false_for_filter_lt      ... ok  (completeness_proved=false)
test backend::plonky3::tests::test_completeness_proved_false_for_join           ... ok  (completeness_proved=false)
test backend::plonky3::tests::test_completeness_proved_false_for_groupby        ... ok  (completeness_proved=false)
test backend::plonky3::tests::test_adversarial_join_zero_results_verifies_with_warning  ... ok
test backend::plonky3::tests::test_adversarial_filter_gt_zero_sum_verifies_with_warning ... ok
test backend::plonky3::tests::test_plonky3_join_completeness_gap_is_documented  ... ok
```

### FRI rejection messages (from actual test output)

| Attack vector | Rejection message |
|---|---|
| Single-byte flip in proof bytes | `proof deserialization failed: Hit the end of buffer, expected more data` |
| Zeroed proof body | `plonky3 verification failed: InvalidProofShape(OpenedValuesDimensionMismatch)` |
| Wrong expected_count / expected_sum in PI | `plonky3 verification failed: OodEvaluationMismatch { index: None }` |
| Wrong dataset (snap_lo) in public inputs | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |
| Wrong query_hash in public inputs | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |
| Wrong result_commit_lo in Join | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |
| Wrong filter_val in PI | `plonky3 verification failed: OodEvaluationMismatch { index: None }` |

**Notes on rejection layers:**

- `OodEvaluationMismatch { index: None }` — FRI verifier: a committed polynomial does not evaluate to the expected value at the verifier's random out-of-domain point. This is a cryptographic rejection at the constraint layer — the constraint polynomial changed.
- `InvalidOpeningArgument(InvalidPowWitness)` — FRI verifier: the proof-of-work witness in the proof is invalid for the new Fiat-Shamir transcript hash. Changing any public input (snap_lo, query_hash, result_commit_lo) alters the transcript, invalidating the PoW witness.
- `proof deserialization failed` — postcard binary parse error. A single-byte flip corrupts the length-prefixed encoding before the FRI verifier is reached.

---

## Known Limitations

### Honest security claims

The following are **documented weaknesses**, not implementation oversights. Listed here so that users and evaluators understand the current security boundary.

| Weakness | Impact | Workaround / Fix path |
|---|---|---|
| **WHERE / GROUP BY / JOIN completeness unproved** | A prover can omit rows satisfying the predicate; proof still verifies. `completeness_proved=false` is set and an explicit warning is emitted. Soundness is intact (if sel=1 then predicate holds). | Implement a lookup argument (Logup/Lasso) for full completeness |
| **Sort range check missing** | `sort_diff` consistency is constrained but non-negativity is not range-checked. Without range check, sort order violations with the same multiset could theoretically pass. Two-phase grand-product still enforces multiset equality. | Add range decomposition (32-bit limbs) to `sort_diff` |
| **Filter LT/GT range check missing** | Diff witness column is constrained by consistency only; `diff < 2^32` is not enforced. Adversarial diff values could construct false inequality witnesses. | Add limb decomposition constraint to diff column |
| **Sort permutation challenge source** | Two-phase FRI derives `r` from the committed preprocessed trace (not from verifier transcript). A prover who controls the preprocessed trace could influence `r`. Full soundness requires an extension field challenge directly from the FRI verifier stream. | Derive `r` from a verifier-chosen challenge in the FRI transcript |
| **Snapshot binding is partial** | `snap_lo` is committed in the FRI Fiat-Shamir transcript as a public input, preventing post-proof tampering. However, there is no first-row AIR constraint forcing `local[col_0] == snap_lo`. Binding relies on the FRI public-value mechanism only, not an in-circuit constraint. | Add `builder.assert_eq(local[0], snap_lo_var)` as a first-row constraint |
| **Per-group individual outputs** | Only a single aggregate hash is committed (PI[5]); individual `(key, count, sum)` tuples are not individually verifiable without re-running the full hash. | Commit per-group outputs as a Merkle tree; prove membership |
| **Multi-operator plans rejected** | Cannot prove `ORDER BY` + `GROUP BY` in a single plan. | Implement proof composition / recursive folding |

### Recursive folding (cross-chunk aggregation)

The `fold()` method returns `Err(...)`. For datasets requiring multiple 128-row chunks, proofs are generated per-chunk but not recursively folded into a single root proof.

### In-memory storage only

All dataset and snapshot storage is in-memory. Benchmark results are persisted to `~/.zkdb/benchmark_results/` as JSON files.

### Scalability above 128 rows (current circuit)

The Plonky3 circuit pads to the next power of two with a configured maximum of 128 rows per proof instance. Larger datasets produce multiple independent chunk proofs that are not yet folded.

### Cross-backend comparison (dimensions 5 and 6)

Lookup argument comparison (Logup vs plookup) and field-size comparison (Goldilocks vs BabyBear vs Pasta) require a second SNARK backend. The portable benchmark pack is ready for this.

---

## Development

```bash
# Build (Plonky3 p3-* crates compile from git, ~30 s first time)
cargo build --release

# Run all 137 tests (debug, ~12 s)
cargo test

# Run all 141 tests (release, ~1.4 s)
cargo test --release

# Start API server
cargo run --release -- serve
```

### Key Dependencies

| Crate | Source | Purpose |
|---|---|---|
| **`p3-uni-stark`** | **git main (Plonky3/Plonky3)** | **Real FRI-STARK proving** |
| `p3-field` | git main | Goldilocks field arithmetic |
| `p3-air` | git main | AIR constraint interface |
| `p3-challenger` | git main | DuplexChallenger (Fiat-Shamir) |
| `p3-fri` | git main | FRI polynomial commitments |
| `p3-merkle-tree` | git main | MerkleTreeMmcs commitment |
| `p3-poseidon2` | git main | Poseidon2 hash (width-8) |
| `p3-goldilocks` | git main | Goldilocks field definition |
| `p3-dft` | git main | Two-adic NTT (parallel) |
| `tokio` | 1 | Async runtime |
| `axum` | 0.7 | HTTP framework |
| `sqlparser` | — | SQL parsing |
| `blake3` | 1 | Query hash, content-addressed IDs |
| `serde` / `postcard` | 1 | Binary proof serialization |
| `clap` | 4 | CLI |
| `uuid` | 1 | Run / suite / dataset IDs |
| `rand` | 0.8 | Deterministic dataset generation |
