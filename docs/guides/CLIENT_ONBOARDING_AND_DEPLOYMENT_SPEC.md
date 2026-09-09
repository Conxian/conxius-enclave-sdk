# Conxian Ecosystem: Client Purchasing, Installation & Deployment Specification

## 1. Executive Summary & Product Offerings
Conxian provides a hardware-backed, protocol-first, multi-chain settlement and signing ecosystem. Clients integrate Conxian primitives through three product offerings across three runtime lanes (Managed, Enterprise, Operator):

- **Enterprise Vault**: Enterprise Sovereign Vault License (`conxius-enclave-sdk` + `conxian-nexus`) with self-hosted AWS Nitro Enclaves / Android StrongBox, Neon PostgreSQL, and Redis.
- **Managed Settlement Gateway**: Managed Rail Proxy Subscription (`conxian-gateway` + `lib-conxian-core`) with Conxian-hosted Enclaves, ISO 20022 Financial Bridge, and Multi-chain Solver Network.
- **Operator Threshold Signer**: Decentralized Signer Operator Node (`conxius-enclave-sdk` + FROST/Fedimint) with Bare-metal/Cloud TEE, Distributed Replay Store, and ROAST Coordinator.

## 2. End-to-End Client Purchasing & Onboarding Workflow

### Step 1: Purchasing & Entitlement Provisioning
1. Commercial Agreement & Organization ID: Client registers on `conxian-business` (Control Plane) and receives an Organization ID (`org_...`) and API Key Pair (`ck_live_...` / `ck_test_...`).
2. License Key & License Attestation: Client is issued an asymmetric signed License Token (`.conxian-license`) binding Organization ID, allowed features (`groth16`, `fedimint-crypto`, `frost-crypto`), and signing volume quotas.

### Step 2: Client Required Inputs & Environment Configuration
- AWS Nitro Enclave (if AWS Enterprise): AWS KMS Key ARN, KMS Key Identifier Hash (SHA-256 of ARN: `3023bd69185b63a2d3e28853def2a77f50fc11cf0ab7698c546716fbc86771e7`), EIF Enclave Measurements (PCR0, PCR1, PCR2).
- Android StrongBox (if Mobile/Android Enterprise): Play Integrity API Key and Service Account JSON, Certificate Chain Attestation Roots.
- Database Connection String: Neon PostgreSQL connection string (`postgres://user:pass@ep-xyz.neon.tech/neondb?sslmode=require`).
- Idempotency & Replay Cache: Redis URI (`redis://:pass@redis.client-domain.com:6379/0`).
- Blockchain RPC Endpoints: Bitcoin L1 RPC/Electrum/Esplora, Ethereum/EVM JSON-RPC, Solana RPC, Stacks RPC, Lightning LND/LDK endpoint.

## 3. Installed System Components & Architecture
- `conxius-enclave-sdk`: Core Rust library / C-FFI / WASM binding providing Universal Chain Signer (UCS), hardware attestation verification, zeroized secret buffers (`WasmSecretBuffer`), and cryptographic primitives (ZF FROST, BLS12-381 DLEQ proofs, Groth16 verifier).
- `conxian-nexus`: High-throughput delivery runtime connecting SDK signing operations with Neon PostgreSQL (`DATABASE_URL`) and Redis for durable, atomic, consume-once idempotency (`IdempotencyStore` / `ReplayStore`).
- `conxian-gateway`: Edge middleware bridging ISO 20022 messaging, ERC-7683 intent routing, and competitive solver ranking (`RailProxy`).

## 4. Cross-Asset Connectivity & Deployment Verification
Using the 4-layer connection graph (Attestation -> Identity -> Storage -> Settlement), clients verify connectivity across all 42 supported asset types:
- Bitcoin / L2s: Bitcoin Mainnet (SegWit/Taproot), Lightning (BOLT11/BOLT12/BIP-353), Stacks (Nakamoto), Liquid, Ark, BitVM2.
- EVM Chains: Ethereum, Arbitrum, Base, Polygon, BSC, Avalanche, Optimism.
- Dynamic L1s: Solana Native & SPL Tokens, Stellar (StrKey G-prefixed), XRP Ledger (Base58Check), Cosmos Hub (Bech32).

## 5. Unified Installer & Management CLI Design (`conxius-ctl`)
Complete client onboarding 4-step command walkthrough:
1. `conxius-ctl doctor` (verify prerequisites, Docker, Nitro CLI, Neon DB)
2. `conxius-ctl auth login --license-file .conxian-license --org-id org_client_12345`
3. `conxius-ctl deploy --lane enterprise --database-url postgres://...`
4. `conxius-ctl test-connectivity --all-chains`

## 6. Recommendations & Next Steps
1. Publish IaC Blueprints: Provide Terraform and AWS CDK templates in `conxius-platform`.
2. Integrate `conxius-ctl`: Develop `conxius-ctl` as a standalone Rust crate in `conxius-platform`.
3. Automate Health Monitoring: Embed Prometheus metrics and OpenTelemetry tracing endpoints in `conxian-nexus` and `conxian-gateway`.
