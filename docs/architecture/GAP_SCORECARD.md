# Conclave SDK: Research & Implementation Gap Scorecard (v0.2.8)

## Overview
This document tracks missing production-path logic, architectural gaps, and research requirements for the Conclave SDK.

## Technical Gaps

### 1. FROST Threshold Signatures (CON-1302)
- **Status**: Researching
- **Requirement**: Implement FROST threshold signature manager (RFC 9591).

### 2. Fedimint Community Liquidity Adapter (CON-1304)
- **Status**: Researching
- **Requirement**: Research fedimint-sdk and implement an adapter for community-governed liquidity.

## Research Backlog
- **Ark Stateless Recovery**: Multi-threaded scanner implementation.
- **BitVM2 Aggregation**: MuSig2-based Taproot tree aggregation (Implemented v0.2.8).
- **OP_CAT Covenants**: Recursive covenant primitives (Implemented v0.2.8).
- **ERC-7683 Solver Selection**: Ranking algorithm (Implemented v0.2.8).
