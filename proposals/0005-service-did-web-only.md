# AFAP-0005: Restrict `service_did` to `did:web`

**Status:** Withdrawn
**Author:** Editor
**Filed:** 2026-05-25
**Withdrawn:** 2026-05-25
**Affects:** None (withdrawn before acceptance)

## Withdrawal note

This proposal is withdrawn. The motivation for tightening
`service_did` to `did:web` rested on the premise that `did:web`
provided a meaningfully stronger identity than `did:key` for
*service* identifiers — specifically, an anchor in DNS+TLS via DID
resolution of `/.well-known/did.json`.

That premise does not hold in v0.1. `core.md` §3.1.2 governs DID
resolution for *account* DIDs that services accept, not for the
service's own `service_did`. No part of the protocol resolves the
service's DID. Observation of representative v0.1 deployments
confirms the gap: `artidrop.ai` declares
`service_did: "did:web:artidrop.ai"` while
`https://artidrop.ai/.well-known/did.json` returns HTTP 404. The
declared DID has no published verification method; the difference
between `did:web` and `did:key` for `service_did` is, in v0.1,
cosmetic.

Tightening a decorative field is unjustified spec churn. If a
future AFAP makes `service_did` load-bearing — for example by
requiring the discovery document itself to be signed by the
service's DID, as §12.8 of `core.md` flags as future work — the
question of which DID methods to permit for that field should be
revisited then, against the actual security properties the new
mechanism depends on.

AFAP-0003's reframed §D.4 (challenge-based registration, no
DID-key signing required) makes the `did:web` vs `did:key`
distinction operationally irrelevant for directory registration:
authentication is host-based and works identically for either
method.

This file is preserved as a record of the design discussion.

## Summary

Tighten §4.3 of `core.md` so that the `service_did` field in
`/.well-known/afauth` MUST use the `did:web` method. The current text
SHOULDs `did:web` and permits `did:key` "for niche service-to-service
contexts." This AFAP removes the `did:key` carve-out, leaving a single
trust anchor — DNS + TLS — for every conforming service's identity.

Account identifiers (§3.1) are **unchanged**: agents and accounts MAY
continue to use `did:key`. The change is scoped to the service-side
identifier published in the discovery document.

## Motivation

§4.3 today reads:

> Implementations SHOULD use `did:web:<host>` so the service's identity
> is anchored in DNS and TLS rather than in a self-issued public key.
> `did:key:...` is permitted but provides no authority anchor — a
> hostile party that controls the connection on which the discovery
> document is fetched can claim any `did:key` value — and is
> appropriate only for niche service-to-service contexts.

The carve-out has three costs and no observed user:

1. **No domain anchor.** A `did:key` `service_did` carries no
   information about who operates the service. The discovery_url host
   is the only anchor a human consumer has, which is exactly what
   `did:web` already encodes inside the DID. Carrying the same anchor
   in two places — one inspectable from the identifier, one only after
   a fetch — is strictly worse than carrying it in one.
2. **No in-place key rotation.** Per §3.1.1 and §8.1, the `did:key`
   identifier *is* the public key. A compromised service signing key
   cannot be retired without rotating to a new `service_did`, which
   breaks every agent already attached to the service. `did:web`'s
   §3.1.2 rotation flow — publish a new verification method in the DID
   document, keep the identifier — has no `did:key` equivalent.
3. **Carve-outs in AFAP-0003.** The directory proposal currently
   carries a `did:key`-specific "no domain anchor" UI indicator (§D.3),
   a separate identity-anchor argument (§D.3), and a special "no
   in-place rotation" paragraph (§D.4) — all to keep the door open
   for a usage pattern §4.3 itself calls niche.

Tightening §4.3 to MUST collapses the carve-outs into a single uniform
rule: a service identity is a DNS-anchored authority. The account
identifier story is independent and unaffected — accounts remain
agent-side, often ephemeral, and frequently per-service derived
(§3.3), all of which `did:key` serves well.

No reference implementation, conformance vector, or schema example
currently exercises a `did:key` `service_did`. The change is therefore
a tightening of the standard against an absent population, not a
deprecation of deployed usage.

## Specification

### Replacement text for §4.3 `service_did` bullet

Replace the existing `service_did` bullet in §4.3 with:

> - `service_did` (string): A DID identifying the service.
>   Implementations MUST use the `did:web` method ([W3C-DID-WEB]) so
>   that the service's identity is anchored in DNS and TLS. The
>   `did:key` method MUST NOT be used for `service_did`; `did:key` has
>   no DNS authority anchor and no in-place key rotation (§3.1.1,
>   §8.1), neither of which a long-lived service identity can give up.
>   This restriction applies only to the service-side identifier;
>   account identifiers MAY continue to use `did:key` per §3.1.

### Schema change

In `spec/schemas/well-known.json`, tighten the `service_did` property:

- `pattern`: change `^did:(web|key):.+` to `^did:web:.+`.
- `description`: replace with: *"The service's own DID. MUST use the
  `did:web` method; see core.md §4.3. `did:key` is reserved for
  account identifiers (§3.1) and is not permitted here."*

### Knock-on edits to AFAP-0003

AFAP-0003 §D.3 (Identity model) drops the `did:key` bullet entirely,
including the "no domain anchor" UI rendering requirement.

AFAP-0003 §D.4 (Listing protocol) drops the "For `did:web` listings"
qualifiers (the directory always resolves `did:web`) and removes the
final paragraph documenting `did:key` rotation behaviour.

AFAP-0003 §"Security and privacy considerations" / "First-registration
hijack" drops the "For `did:web` listings" qualifier for the same
reason.

These edits land in AFAP-0003 alongside this AFAP. They are not
independent changes; they are bookkeeping that follows from the
core.md tightening above.

## Compatibility

**Wire-tightening, not wire-breaking against any known deployment.**

- The reference Worker, the TypeScript SDK fixtures, the discovery
  test vectors, the signature test vectors, and every example in
  `core.md` use `did:web:api.example.com` for `service_did`. No
  artefact needs to be regenerated.
- Any v0.1 service that today publishes `service_did:
  "did:key:..."` becomes non-conforming. None are known. Such a
  service migrates by:
  1. Obtaining DNS + TLS for the discovery host (it already has
     these, since `/.well-known/afauth` is served over HTTPS).
  2. Publishing a DID document at `https://<host>/.well-known/did.json`
     containing its existing Ed25519 verification key.
  3. Changing `service_did` in `/.well-known/afauth` from
     `did:key:zX…` to `did:web:<host>`.
  4. Notifying attached agents through whatever channel the operator
     already uses for service announcements.
- Agents that previously accepted both methods MAY continue to accept
  both at no cost; the change is a tightening on what conforming
  services *publish*, not on what agents *parse*. Verifiers MAY treat
  a `did:key` `service_did` as a discovery-document validation failure
  per the schema change above.

## Security and privacy considerations

**Removes a no-rotation footgun.** With `did:key` permitted for
services, a controller whose signing key was compromised had two
options: rotate to a new `service_did` (breaking every attached agent)
or continue using the leaked key. Restricting to `did:web` makes the
§3.1.2 rotation flow available to every conforming service — the
controller publishes a new verification method, the identifier
persists, and attached agents continue to work.

**Single trust anchor across the protocol's service surface.** Every
service-side authority claim now reduces to DNS + TLS for the service
host: the discovery-document fetch (§4.1), DID-document resolution
(§3.1.2), and signed listing submission (AFAP-0003 §D.4). One anchor
to harden (HSTS, CAA, MPIC corroboration in future work) rather than
two.

**§12.8 (Discovery document integrity) is unchanged.** The threat
model there — TLS compromise lets an attacker rewrite the document,
including `service_did` — is independent of which DID method is
permitted. The mitigation guidance (HTTPS-only, HSTS, out-of-band key
pinning) applies identically.

**Account-side `did:key` is preserved.** §13.1's note that a persistent
`did:key` is a correlatable pseudonymous identifier applies to
accounts and is not affected by this AFAP.

**No new attack surface.** Restricting the permitted set of values for
a published field cannot, by construction, enable an attack that
permitting more values would have prevented.

## Alternatives considered

- **Keep the current SHOULD.** Rejected. The SHOULD has produced no
  observed non-`did:web` deployments, and the carve-out forces
  AFAP-0003 to specify UI and operational special cases for a usage
  pattern §4.3 itself calls niche. The cost is paid by every
  implementer of the directory, every UI consumer of listings, and
  every reader of the spec; the benefit accrues to a hypothetical
  user nobody has met.

- **Restrict only in the canonical directory.** Considered in the
  drafting of this AFAP. Rejected: a stricter directory policy than
  the protocol leaves the underlying footgun in place for any
  consumer outside `afauth.org/registry`, and creates a "directory
  rejects, protocol permits" asymmetry that complicates the AFAP-0003
  story without removing the root cause.

- **Permit `did:key` for narrow service-mesh / internal use.**
  Rejected. Any service capable of serving `/.well-known/afauth` over
  HTTPS already has a DNS + TLS anchor, and can therefore mint
  `did:web:<host>` at zero marginal cost. Internal deployments that
  legitimately lack public DNS can run private extensions under their
  own naming rules; they do not need to be permitted at the conforming
  surface.

- **Hold for v0.2.** Rejected. The carve-out is in the current
  working draft and is propagating into AFAP-0003. Removing it now —
  while v0.1 is still pre-stabilisation — is cheaper than removing it
  after the first wave of deployments has internalised the SHOULD.

- **Deprecate but do not remove (mark `did:key` for `service_did` as
  "deprecated, removed in v0.2").** Rejected as over-engineered for a
  pre-stabilisation working draft with no known deployments. There is
  nothing to grandfather.

## References

- §3.1.1, §3.1.2, §4.3, §8.1, §12.8 of [`../spec/core.md`](../spec/core.md)
- AFAP-0003: Non-normative service directory at afauth.org —
  [`0003-service-directory.md`](0003-service-directory.md), §D.3, §D.4
- **[W3C-DID-WEB]** DID method `did:web`
- **[W3C-DID-KEY]** The did:key Method v0.7 (preserved for account
  identifiers, see §3.1.1)
