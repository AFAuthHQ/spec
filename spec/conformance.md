# AFAuth Conformance

**Status:** Stub. A complete conformance test suite is planned before v0.1 final.

This document describes what an AFAuth implementation must support to call itself "AFAuth-conformant." It is the authoritative reference for that claim; the protocol specification ([`core.md`](core.md)) provides the underlying normative requirements.

## Scope

An AFAuth-conformant implementation is either an **agent** that signs requests according to the protocol, or a **service** that verifies them and operates the account lifecycle. Conformance is asserted separately for each role.

This document does NOT specify:

- What operations an agent may perform at any given account state beyond the §7.5 owner-binding floor (out of scope per §1.3).
- The user interface of the claim ceremony (service responsibility per §12.3).
- The treatment of pre-claim account state at claim time (service responsibility per §12.7).

## Service conformance (planned probes)

A conforming service MUST:

1. **Discovery.** Serve a valid `/.well-known/afauth` document per the schema, including all `required` endpoints (`accounts`, `owner_invitation`, `claim_page`, `claim_completion`).
2. **Signature verification.** Accept the §5.2 covered components and parameters; reject requests with extra or missing components; honour `created` and `expires`; maintain a `(keyid, nonce)` replay set covering at least `expires - created + skew_tolerance`.
3. **State machine.** Implement all and only the transitions in Appendix A. In particular, transition `UNCLAIMED → INVITED → CLAIMED` only via the §7 flow; never bind an owner whose authenticated identity does not match `pending_email` (§7.4).
4. **Two-step verify (§7.1).** Reject any flow in which the agent's signature alone binds ownership.
5. **Owner-binding floor (§7.5).** Reject agent-signed owner-binding operations post-claim with `403 Forbidden` and `owner_binding_blocked`.
6. **Invitation atomicity (§7.3).** At most one pending invitation per account at any time; atomic replacement; invalidated tokens MUST fail with `410 Gone`.
7. **`attested_only` honouring (§9, §6.3).** Services declaring `unclaimed_mode = "attested_only"` MUST reject implicit signup lacking attestation with `attestation_required`, without creating the account.
8. **Error codes (§11).** Use the reserved codes for the conditions they describe.

## Agent conformance (planned probes)

A conforming agent MUST:

1. **Discovery.** Fetch and honour `/.well-known/afauth` before signup; respect the declared `signature_algorithms` and `billing.unclaimed_mode`.
2. **Identity.** Generate a valid `did:key` (or use `did:web`) account identifier per §3.1, including canonical multibase/multicodec encoding.
3. **Signing.** Produce signatures with all §5.2 covered components and parameters; bound `expires - created` ≤ 300 seconds; use a fresh nonce per request.
4. **Key handling.** Store private keys per §3.2 / §12.1 recommendations; rotate per §8.
5. **Claim flow.** Initiate the two-step invitation per §7.2; treat `410 Gone` on an invitation as a normal expiry condition.

## Versioning

This document tracks the protocol version it describes. Future revisions will use additive probes for non-breaking protocol changes and a new major version for breaking changes.

## Status

A test vector suite (Appendix C of `core.md`) and an executable conformance harness are open work items. Contributions welcome via the proposals process (see [`../proposals/`](../proposals/README.md)).
