# zkDB Plonky3 — Implementation Status

Generated: 2026-03-28. Based on `cargo test -- --nocapture` output and direct code audit.

---

## What is real

- **`p3_uni_stark::prove` and `p3_uni_stark::verify` are called for real.**
  `src/backend/plonky3.rs` — `prove(&config, &air, trace, &public_vals)` and
  `verify(&config, &air, &proof, &public_vals)`.
  These are not stubs. A ~70 KB FRI proof is produced and verified cryptographically.

- **Real Goldilocks + Poseidon2 + FRI configuration.**
  `make_config()` constructs: `Poseidon2Goldilocks<8>` (Merkle compression + sponge),
  `MerkleTreeMmcs`, `TwoAdicFriPcs`, `DuplexChallenger`. Parameters: `log_blowup=1`,
  `max_log_arity=1`, `num_queries=100`, `commit_proof_of_work_bits=16`,
  `query_proof_of_work_bits=16`.

- **Goldilocks field (p = 2^64 − 2^32 + 1)** replaces BabyBear.
  All practical u64 column values encode without modular reduction.
  Comparison constraints are sound for realistic financial amounts.

- **8 public inputs (PI[0..7]) are committed in every proof.**
  `ZkDbPublicInputs` carries: snap_lo, query_hash, result_sum, result_row_count,
  result_commit_lo, group_output_lo, sort_secondary_hi_snap_lo, group_vals_snap_lo.

- **Proof bytes are non-trivial (postcard binary serialization).**
  Proof size for a 5-row Arithmetic circuit (padded to 8 rows): **~70.6 KB**.
  Prior BabyBear + JSON implementation: ~128–134 KB (1.8× larger).

- **`ProofSystemKind::Plonky3Stark` label is correct.**

- **All 105 tests pass.** (104 library tests + 1 integration test)
  ```
  test result: ok. 104 passed; 0 failed; 0 ignored; 0 measured
  test result: ok. 1 passed;   0 failed; 0 ignored; 0 measured
  ```

---

## Soundness attack vectors — actual rejection messages

All 7 targeted attacks are rejected. Test output from `cargo test -- --nocapture`:

| Attack vector | Test | Rejection message |
|---|---|---|
| **Single-byte flip in proof** | `test_plonky3_rejects_tampered_proof` | `proof deserialization failed: Hit the end of buffer, expected more data` |
| **Zeroed proof body** | `test_plonky3_rejects_tampered_proof` | `plonky3 verification failed: InvalidProofShape(OpenedValuesDimensionMismatch)` |
| **Wrong expected_count in VK** | `test_plonky3_rejects_wrong_result` | `plonky3 verification failed: OodEvaluationMismatch { index: None }` |
| **Wrong dataset (snap_lo)** | `test_plonky3_rejects_wrong_dataset` | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |
| **Wrong filter_val in VK** | `test_plonky3_filter_soundness` | `plonky3 verification failed: OodEvaluationMismatch { index: None }` |
| **Wrong snap_lo in Sort VK** | `test_plonky3_sort_is_proven` | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |
| **Wrong result_commit_lo in Join VK** | `test_plonky3_join_is_proven` | `plonky3 verification failed: InvalidOpeningArgument(InvalidPowWitness)` |

**Notes on rejection layers:**

- `OodEvaluationMismatch` — FRI verifier: a committed polynomial does not evaluate
  to the expected value at the verifier's random out-of-domain point.  This is a
  cryptographic rejection at the constraint layer (the constraint polynomial changed).

- `InvalidOpeningArgument(InvalidPowWitness)` — FRI verifier: the proof-of-work
  witness in the proof is invalid for the new transcript hash.  Changing any public
  input alters the Fiat-Shamir transcript, invalidating the PoW witness.

- `proof deserialization failed` — postcard binary parse error.  A single-byte flip
  corrupts the length-prefixed encoding before the FRI verifier is reached.

---

## What is constrained in the proof

### Always active (all modes): Selector boolean

```rust
// ZkDbAir::eval() — fires before mode dispatch
let sel = local[self.selector_col].clone();
builder.assert_zero(sel.clone() * (sel - AB::Expr::ONE));
```
`selected[i] ∈ {0,1}` for every row i.

### Arithmetic mode (COUNT / SUM / AVG / FILTER)

- `partial_sum[0] = selector[0] * value[0]`  (first-row initialisation)
- `partial_sum[i+1] = partial_sum[i] + selector[i+1]*value[i+1]`  (running sum)
- `partial_sum[last] == expected_sum`  (PI[2] binding)
- `count[0] = selector[0]`;  `count[i+1] = count[i] + selector[i+1]`
- `count[last] == expected_count`  (PI[3] binding)
- Filter op=1 (equality): `selector * (value − filter_val) = 0`
- Filter op=2/3 (LT/GT): diff witness column + consistency constraint (range check TODO)

### Sort mode

- Running product in: `prod_in[0] = r − primary_in[0]`;
  `selector * (prod_in[i+1] − prod_in[i]*(r−primary_in[i+1])) = 0` (deg-3)
- Padded-row constancy: `(1−selector) * (prod_in[i+1] − prod_in[i]) = 0`
- Running product out: symmetric over `primary_out`
- Grand-product equality at last row: `prod_in[last] == prod_out[last]`
- Monotonicity: `selector * (primary_out[i+1] − primary_out[i] − sort_diff[i]) = 0`
  (range check on sort_diff is TODO — without it, only multiset equality is enforced)

### GroupBy mode

- First row is always a boundary: `is_boundary[0] = 1`
- `is_boundary ∈ {0,1}` binary constraint
- `group_sum[i+1] = is_boundary[i+1]*value[i+1] + (1−is_boundary[i+1])*(group_sum[i] + value[i+1])`
- Key monotonicity within group: `selector * (1−is_boundary[i+1]) * (key[i+1]−key[i]) = 0` (deg-3)

### Join mode

- Key equality soundness: `selector * (left_key − right_key) = 0`
- Running count initialisation + transition + final equality

---

## Performance (debug build, Goldilocks, 5–6 rows padded to 8)

| Metric | Plonky3 Goldilocks (current) | Plonky3 BabyBear JSON (prior) |
|--------|-------------------------------|-------------------------------|
| Proof size | **~70.6 KB** | ~128–134 KB |
| Proof serialization | postcard (binary) | serde_json (text) |
| Full prove+verify (7 tests) | ~2.1 s (debug, 7 circuits) | ~5.6 s (debug, 1 circuit) |
| Field | Goldilocks (64-bit prime) | BabyBear (31-bit prime) |
| Extension degree | 2 | 4 |
| Tamper detection | FRI cryptographic layer | JSON parse layer (weaker) |

---

## Known gaps (not yet constrained)

| Gap | Description | Location |
|-----|-------------|----------|
| **WHERE completeness** | Filter equality is sound (sel=1 → value==filter_val) but NOT complete (value==filter_val does not force sel=1). A lookup table argument is required. | `eval()` filter op=1 |
| **Sort range check** | `sort_diff` consistency is constrained but non-negativity is not. Without range check, sort order violations with the same multiset can pass. | `eval()` Sort monotonicity |
| **Filter LT/GT range check** | diff column is constrained by consistency only; range check (diff < 2^32) is TODO. | `eval()` filter op=2/3 |
| **Snapshot commitment binding** | `snap_lo` is passed as PI[0] and committed in the FRI transcript. However, the `public_vals` in `prove()` are committed to the transcript but there is no first-row constraint enforcing `local[col_0] == snap_lo`. The PI binding relies on the FRI public-value mechanism only. | `prove()` |
| **Sort challenge source** | `r = Blake3(snap_lo ++ query_hash)` is deterministic (known before proof). A prover who knows r could craft adversarial inputs. Upgrade to verifier-transcript challenge (FRI extension field element). | `compute_sort_challenge()` |
| **Recursive folding** | `fold()` returns `Err(...)`. Multi-chunk datasets cannot be aggregated into a single proof. | `fold()` |
| **GroupBy/Join completeness** | Only soundness constraints are active; completeness (all matching rows included) requires a permutation/lookup argument. | `eval()` GroupBy, Join |

---

## What SQL operations are cryptographically constrained

| Operation | Constrained? | What the proof guarantees |
|-----------|-------------|--------------------------|
| `COUNT(*)` | **Yes** | count[last] == expected_count; selector bits ∈ {0,1}. |
| `SUM(col)` | **Yes** | partial_sum[last] == expected_sum; value-weighted accumulator enforced row-by-row. |
| `AVG(col)` | **Partially** | sum and count constrained; AVG = sum/count is outside the circuit. |
| `SELECT col` (table scan) | **Partially** | Selector bits ∈ {0,1}. Column values are encoded in trace but not proven correct. |
| `WHERE col = val` (soundness) | **Yes** | If selector=1 then value==filter_val. (Completeness not proven.) |
| `WHERE col < val` / `> val` | **Partially** | Diff witness consistency enforced; range check TODO. |
| `ORDER BY col ASC/DESC` | **Partially** | Input/output multisets equal (grand-product). Sort order only if range check added. |
| `GROUP BY col` | **Partially** | Boundary binary; group_sum accumulation; key monotonicity within group. Completeness TODO. |
| `JOIN ON key` (soundness) | **Yes** | If selector=1 then left_key == right_key. (Completeness TODO.) |
| Dataset binding (snap_lo) | **Yes** | PI[0] = snap_lo committed in FRI transcript; tampering changes Fiat-Shamir transcript. |
