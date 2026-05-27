# AFAP-0006: Reserve `afauth-bootstrap` as a recognized attestor

**Status:** Draft
**Author:** Editor
**Filed:** 2026-05-27
**Affects:** core.md §10

## Summary

Reserve `afauth-bootstrap` as a recognized attestor identifier in §10.3,
operated by afauth.org as the default attestor for v0.1 of the protocol.
The role of the bootstrap attestor is narrow: bind an agent's account
DID to a human-controlled account and issue a short-lived, audience-
bound JWT that signals the binding to consuming services. Verification
is offline against a published JWKs document. The protocol takes no
opinion on what access a service should grant in response to any
particular signal.

This AFAP reserves the identifier and pins the wire-level shape. It
does not specify operator policy, abuse handling, or commercial terms.

## Motivation

§10.3 today recognizes three classes of attestor identifier — platform
(Entra, GCP, AWS), commerce (Stripe, FIDO AP2, Mastercard), and
service-operator HMAC. All of the recognized platform and commerce
attestors are operated by parties that will not integrate with a
working-draft protocol at zero adoption. Service-operator HMAC is, by
definition, first-party — it cannot vouch for an agent across the
open ecosystem.

The result: §9.2's `attested_only` mode and the rest of §10 are
unreachable from a clean v0.1 deployment. A service that wants to gate
free-tier signups behind "some human signal sits behind this agent"
has no attestor to list in `billing.accepted_attestors`. The service
either rolls its own HMAC scheme — defeating the cross-service goal —
or accepts unattested signups and bears the abuse risk.

A neutral, openly-operated attestor at the protocol level closes the
bootstrap hole. Long-term, platform and commerce attestors will join
§10.3 when ecosystem adoption warrants their attention; until then,
`afauth-bootstrap` keeps the surface alive.

## Specification

### Replacement text for §10.3 first paragraph and list

Replace the existing §10.3 list with:

> This specification reserves four classes of attestor identifier:
>
> - **Bootstrap attestor**: `afauth-bootstrap`. Operated by afauth.org.
>   Vouches that an agent's account DID is bound to a human-controlled
>   account verified by one of the methods enumerated in §10.3.1.
> - **Platform attestors**: `microsoft-entra-agent-id`,
>   `google-cloud-agent-identity`.
> - **Commerce attestors**: `fido-agent-payments`,
>   `mastercard-verifiable-intent`, `visa-trusted-agent`.
> - **Service-operator HMAC**: For first-party agents, services MAY
>   accept tokens signed with a shared symmetric key under an
>   identifier they define.

### New subsection §10.3.1 — Bootstrap attestor (`afauth-bootstrap`)

Insert immediately after §10.3:

> ### 10.3.1 Bootstrap attestor (`afauth-bootstrap`)
>
> The bootstrap attestor issues JWTs that satisfy §10.2 and
> additionally:
>
> - `iss` MUST be the string `afauth-bootstrap`.
> - `aud` MUST be the `service_did` of the destination service. A
>   service MUST reject a token whose `aud` does not match its own
>   `service_did`.
> - `iat` MUST be present. `exp - iat` MUST NOT exceed 900 seconds.
> - `verification` (string) MUST be present. Defined values:
>   `"email"`, `"oauth"`, `"payment"`. Consuming services MUST ignore
>   unknown values rather than rejecting the token, so that future
>   values can be added without breaking existing verifiers.
>
> The JWT header MUST include a `kid` that resolves to a key
> published in the JWKs document at
> `https://afauth.org/.well-known/jwks.json`. Consuming services MUST
> verify tokens offline against that document. The attestor MUST
> publish a new `kid` at least one maximum-TTL (900 seconds) before
> first use, so that caches can refresh without an outage window.
>
> The bootstrap attestor MUST NOT include personal data (email
> address, phone number, payment details, government identifiers) in
> any claim. Future claims that signal additional context MAY be added
> without revising this AFAP, provided they preserve the
> offline-verification property and the privacy constraint above.
>
> The spec takes no opinion on what access a service grants in
> response to any particular `verification` value, nor on any
> ordering between values. The `verification` claim is a categorical
> signal; the service's policy is local.

## Compatibility

**Wire-additive, no breaking change.**

- §10.2 already permits attestor-specific claims; this AFAP defines
  the claims a consumer can rely on when `iss == "afauth-bootstrap"`.
- Services that do not list `afauth-bootstrap` in
  `billing.accepted_attestors` are unaffected.
- An agent that presents an `afauth-bootstrap` token to a service
  that does not accept it receives the same rejection it would for
  any unrecognized attestor — no new error code is needed.
- The reference TypeScript SDK and CLI need to learn the
  `afauth-bootstrap` `iss` value and the JWKs URL. No protocol-level
  surface beyond §10.3 changes.

## Security and privacy considerations

**Single dependency during bootstrap.** Every service that requires
`afauth-bootstrap` shares a dependency on afauth.org publishing the
JWKs document and signing tokens. Offline verification bounds the
runtime blast radius: a brief afauth.org outage does not interrupt
in-flight requests at consuming services; only token reissuance is
affected. The 900-second `exp` cap bounds revocation latency.

**Audience binding prevents redirection.** Pinning `aud` to the
destination `service_did` prevents an agent from replaying an
attestation issued for service A against service B.

**No PII in claims.** The bootstrap attestor emits a categorical
`verification` value, never the underlying address, number, or payment
metadata. Consuming services receive a signal, not an identity.

**Pairwise `sub` is preserved.** §3.3's per-service derivation default
applies to the agent's account DID and therefore to the attestation's
`sub`. The bootstrap attestor relays whatever account DID the agent
presents and adds no new cross-service correlatability beyond what the
agent itself chose.

**Operator integrity is out of scope.** This AFAP does not constrain
how afauth.org performs underlying verification (email-confirmation
flow, OAuth provider selection, payment processor, abuse handling).
Those are operator-policy questions. The protocol surface is the JWT
shape and the JWKs endpoint.

**Governance.** afauth.org acts as both spec editor and bootstrap
attestor operator at v0.1. This is acknowledged. If, at a later date,
neutrality becomes operationally relevant — for example because
platform or commerce attestors require it as a condition of joining
§10.3 — a future AFAP may move the bootstrap attestor under a
distinct identifier and entity. The wire shape defined here is
unchanged by that move.

## Alternatives considered

- **Do not reserve a default attestor; rely on platform/commerce
  attestors.** Rejected. At v0.1 adoption, none of the §10.3 attestors
  will integrate. `attested_only` mode is unreachable without a
  bootstrap option.
- **Define normative quota tiers per `verification` value.** Rejected.
  Useful free-tier quota varies by service class — search, deep
  research, codegen — by orders of magnitude. Any number the spec
  picks is wrong for most services. The operator decides.
- **Include cross-service abuse-history or revocation claims at v0.1.**
  Rejected as scope creep. The bootstrap thesis — services grant
  free-tier access to attested agents — does not depend on a
  cross-service data model. The `verification`-claim shape leaves
  room for additional claims later without revising this AFAP.
- **Specify an ordinal level (`L1`/`L2`/…) rather than a categorical
  `verification`.** Rejected. Ordinal levels imply an ordering
  services must accept; categorical values let each service rank
  signals according to its own threat model. The latter matches the
  "operator decides" framing.
- **Run the bootstrap attestor under a distinct entity from afauth.org
  for governance neutrality.** Considered. Rejected for v0.1: the
  additional legal and operational overhead is not justified at the
  working-draft stage. The governance note above leaves the door
  open for a later move without wire changes.

## References

- §3.3, §9.2, §10 of [`../spec/core.md`](../spec/core.md)
- [RFC 7519] JSON Web Token
- [RFC 7517] JSON Web Key
