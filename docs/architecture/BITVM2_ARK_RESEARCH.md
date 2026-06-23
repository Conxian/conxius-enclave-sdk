# Research: BitVM2 Aggregation & Ark Stateless Recovery (v1.9.2)

## 1. BitVM2 Aggregation (Recursive SNARKs)
BitVM2 leverages Groth16 SNARKs to verify complex computations on Bitcoin. To handle large proofs within Bitcoin's 100KB block limit and script constraints, BitVM2 employs **script chunking** and **recursive aggregation**.

### Key Findings:
- **Chunking Strategy**: Verification is split into ~364 independent script segments. Each segment is a Taproot leaf.
- **Aggregation**: Multi-party Taproot tree aggregation allows multiple verifiers to participate in the optimistic challenge process.
- **Recursive Verification**: By verifying a SNARK that itself verifies other SNARKs, we can compress large state transitions (e.g., a whole L2 batch) into a single on-chain verification.

### Implementation Path:
- Use `bitvm::groth16::verifier::Verifier::hinted_verify` for generating chunks.
- Integrate `Musig2` for multi-party signature aggregation over the Taproot tree.

## 2. Ark Stateless Recovery
Ark is a layer-two protocol for Bitcoin that uses Virtual UTXOs (V-UTXOs). Stateless recovery is critical for mobile users who might lose local state.

### Key Findings:
- **Blake2s PRF**: Use the Blake2s Pseudo-Random Function to derive V-UTXO seeds from a master secret and a counter/index.
- **Derivation Scheme**:
  ```rust
  let vutxo_seed = Blake2s::evaluate(&master_secret, &index_as_32_bytes)?;
  ```
- **Recovery Flow**: The SDK can re-derive all potential V-UTXO keys by scanning the index range and checking against the Ark ASP (Ark Service Provider).

### Implementation Path:
- Integrate `ark-crypto-primitives` for standardized Blake2s PRF.
- Add `recovery_scan` method to `ArkManager` to reconstruct V-UTXO sets from seed.

## 3. Solver Selection (ERC-7683)
For cross-chain intents, selecting the "best" solver is a competitive process.

### Research Notes:
- **Bidding**: Solvers submit bids (output amount + deadline).
- **Ranking**: The SDK ranks solvers based on yield (output / input) and finality speed.
- **Selection**: Atomic selection happens during the `prepare_intent` phase in `RailProxy`.
