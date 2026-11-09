# RFD: Auth Key Canonicalization and Code Health Cleanup

Date: 2026-05-01
Status: Implemented

## Summary

This workstream fixed a trust-on-first-use signing-key mismatch in the invite and chat flows, brought the repository back to a green `fmt` / `clippy` / `test` state, and removed dead code that had been temporarily tolerated during the repair.

The highest-risk defect was that the same Ed25519 public key was being represented in different base64 alphabets across code paths. Invite flow state used URL-safe base64 without padding, while signed chat wire messages used standard base64 with padding. That made string equality checks reject valid traffic from the same identity.

This RFD records the decisions made to fix that defect and to clean up the adjacent code paths.

## Problem

There were three separate problems in the codebase:

1. Trusted signing keys were compared as raw strings even though the same key could be encoded in different base64 alphabets.
2. The seed verification path still minted credits even though the tests and current trust model expected receipts-only bootstrapping.
3. The repository had accumulated lint failures and dead code, including a split capability-card model and an unused sandbox-lease subsystem.

Together these made the code harder to reason about and allowed correctness to depend on formatting details instead of actual key bytes.

## Goals

- Compare signing keys by decoded bytes, not by presentation format.
- Preserve compatibility with already-written local state.
- Keep the DM flow working without introducing a new wire protocol unless required.
- Return the repo to green `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test`.
- Remove dead code instead of masking it with `#[allow(dead_code)]`.

## Non-goals

- Replace TOFU with a stronger identity model.
- Introduce a separate DM message wire type.
- Add a broader sandbox lease accounting feature. The removed lease code was not wired into production behavior.

## Decisions

### 1. Canonicalize trusted signing keys to standard base64

Trusted signing keys are now canonicalized to standard base64 when persisted, and existing stored values are normalized on read.

Rationale:

- The signed chat wire format already uses standard base64.
- Canonicalizing storage removes ambiguity for new state.
- Read-time normalization preserves compatibility with prior URL-safe values.

### 2. Compare signing keys by decoded bytes

All trust-sensitive comparisons now decode both sides and compare the underlying key bytes. Standard base64 and URL-safe no-pad encodings are both accepted.

Affected paths:

- signed chat message verification
- signed invite signer verification
- targeted DM invite recipient signing-key verification

Rationale:

- The trust decision should depend on the key material, not on its string encoding.
- This avoids a class of regressions if another path later emits a different but equivalent textual form.

### 3. Keep DM as a private-room abstraction

DM remains implemented as a deterministic private room per peer pair. We did not add a separate `"dm_message"` wire type.

Rationale:

- Existing encryption, send, read, invite, and receipt flows already work at the room layer.
- The CLI-level `agora dm <agent-id> [message]` flow is enough for current behavior.
- Adding a new DM-specific wire type would increase protocol surface without solving the actual issue fixed in this workstream.

Consequence:

- A DM is identified by room identity and room membership, not by a message subtype.
- DM-specific behavior should continue to be modeled at the room and invite layer unless a concrete requirement proves otherwise.

### 4. Calibration seeds now bootstrap trust via receipts only

Seed verification no longer mints credits. It issues a work receipt and updates trust, but does not grant balance.

Rationale:

- This matches the current tests and trust model.
- It reduces incentive for farming seed completions as an economic bootstrap path.

### 5. Remove dead code instead of suppressing warnings

We removed or consolidated dead code introduced or exposed during the repair:

- removed the obsolete `AgentCapabilityCard` persistence path
- removed the unused `DiscoveredCapabilityCard` type
- removed unused `reactions` and `muted` wrappers
- removed the dead `process_card_message` helper
- removed the unused sandbox-lease subsystem and its tests
- moved ratchet helper functions in `crypto.rs` under `#[cfg(test)]` because they are test-only

Rationale:

- The repo should not carry duplicate models for the same concept unless both are live.
- Dead subsystems raise maintenance cost and create false work during lint cleanups.

## Capability Card Consolidation

Before this workstream, capability-card ingestion was split:

- live discovery and `card-show` behavior used `CapabilityCard`
- auxiliary event ingestion wrote a different `AgentCapabilityCard` model
- there was also a dead helper intended to populate the live peer-card cache

That split meant the code was carrying two competing representations for capability cards, but only one of them was used by real product paths.

The final state is:

- incoming capability-card events populate the `CapabilityCard` peer-card cache directly
- discovery reads the same peer-card cache
- `agora card-show <agent>` reads the same peer-card cache

This removes the model split and leaves one live path.

## Validation

The implemented workstream was validated with:

- targeted auth and invite tests
- a manual two-home reproduction of the original signing-key mismatch issue
- a full green repository pass:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test`

At the end of the workstream, the full test suite passed cleanly.

## Consequences

Positive:

- invite and chat trust checks are now robust to base64 presentation differences
- DM invite guardrails still work and now share the same key-comparison logic
- capability-card behavior is simpler and internally consistent
- lint and test signals are meaningful again because dead code is gone

Tradeoffs:

- old `cards.json` data from the removed `AgentCapabilityCard` path is no longer part of the live read path
- the unused sandbox-lease experiment was removed instead of being revived

These tradeoffs are acceptable because neither subsystem was active in the product path being exercised.

## Follow-up Work

- If the project later needs stronger identity guarantees, the next step is not another encoding fix; it is replacing or augmenting TOFU with explicit identity binding.
- If DM needs behavior beyond a private-room abstraction, define the concrete requirement first before introducing protocol-level DM message types.
- If sandbox lease accounting becomes a real product feature, it should be reintroduced as a fully wired subsystem with production call sites, not as dormant store-only code.
