# AFAP-0007: Refresh §10.3 recognized attestor identifiers

**Status:** Accepted
**Author:** Editor
**Filed:** 2026-05-27
**Accepted:** 2026-05-27
**Affects:** core.md §10.3; AFAP-0006 §10.3 replacement text

## Summary

Refresh the §10.3 list of recognized attestor identifiers against the
2026 deployed reality:

- Remove `aws-iam-agent`. The name does not match an actual AWS
  product; AWS's agent identity surface is **Bedrock AgentCore** (GA
  October 2025), whose workload access token is documented as opaque
  and first-party-only ("cannot be used for external services"). There
  is no AWS-issued assertion an arbitrary internet service can verify,
  so §10.3's "MUST validate against published verification key" clause
  is unfulfillable.
- Remove `stripe-projects`. The name does not match Stripe's
  agentic-commerce product family (Agentic Commerce Suite, Issuing for
  Agents, Shared Payment Tokens, Link Agent Wallet). Stripe's identity
  primitives are platform-internal; no public verification path
  exists.
- Add `visa-trusted-agent` to commerce attestors. Visa's Trusted Agent
  Protocol (announced October 2025) publishes a JWKS document at a
  stable well-known URL and uses [RFC 9421] HTTP Message Signatures —
  the only commerce-rooted attestor in the current landscape an
  arbitrary internet service can verify without per-merchant
  enrolment.
- Add two informative paragraphs after the bulleted list noting the
  structural constraints of platform attestors (typically tenant-
  scoped audience binding) and commerce attestors (typically
  transaction-scoped assertions). Non-normative; readers calibrate
  expectations.

## Motivation

§10.3 reserves attestor identifiers and obligates services to verify
them against a published key. The current list contains two
identifiers — `aws-iam-agent` and `stripe-projects` — that do not
match real shipped products and that cannot fulfill the verification
obligation:

- **AWS.** AWS shipped Bedrock AgentCore (including AgentCore
  Identity) in October 2025. There is no product called "AWS IAM
  Agent." AgentCore's workload access token is documented as opaque
  and first-party-only. AgentCore is a *consumer* of upstream IdP
  attestations, not a *producer* of externally verifiable ones.
- **Stripe.** "Stripe Projects" was an older Stripe surface unrelated
  to agent identity. Stripe's current agent-relevant primitives
  (SPTs, Issuing for Agents, Link Agent Wallet, agent guardrails) are
  platform-internal — no JWKS, no public verification endpoint, no
  documented third-party verification path.

These identifiers being on the list misleads spec readers: they imply
a viable verification path that does not exist. The §10.3 clause
"Conforming services MUST validate the attestation against the
attestor's published verification key" cannot be honoured for either
identifier.

Meanwhile, the commerce-attestor landscape gained a new entrant in
late 2025–2026 that fits §10.3's verification obligation cleanly.
Visa's Trusted Agent Protocol publishes signing keys at
`https://mcp.visa.com/.well-known/jwks` and signs HTTP messages per
[RFC 9421]. Any service that can fetch a JWKS and validate RFC 9421
signatures can verify a TAP assertion — no per-merchant federation
required. TAP's `agent-browser-auth` tag explicitly covers pre-payment
interactions, so the attestor signal is presentable outside checkout.
It is the most usable commerce attestor against AFAuth's "open
internet" model.

This AFAP also adds two short informative paragraphs after the
bulleted list. Survey work motivating this refresh surfaced a
recurring confusion: readers conflate the legitimacy of an attestor
identifier with its operational fit for AFAuth's open-internet signup
model. Platform attestors are mostly designed for the customer's own
tenant; commerce attestors are mostly transaction-scoped. Calling
these constraints out non-normatively prevents misuse without
restricting reservation.

The working-draft status of v0.1 is the right window for this
cleanup. Removing reserved identifiers becomes more expensive after
stabilisation; the current list has no known deployed consumers of
either `aws-iam-agent` or `stripe-projects`.

## Specification

### Replacement text for §10.3

Replace the entirety of §10.3 with:

> ### 10.3 Recognized attestors
>
> This specification reserves three classes of attestor identifier:
>
> - **Platform attestors**: `microsoft-entra-agent-id`,
>   `google-cloud-agent-identity`.
> - **Commerce attestors**: `fido-agent-payments`,
>   `mastercard-verifiable-intent`, `visa-trusted-agent`.
> - **Service-operator HMAC**: For first-party agents, services MAY
>   accept tokens signed with a shared symmetric key under an
>   identifier they define.
>
> Platform attestors are typically designed around a customer's own
> tenant: the assertion's audience claim names a relying party
> pre-registered in the attestor's directory. A service that accepts
> a platform attestor identifier should expect to set up per-tenant
> federation (or equivalent) to make the audience binding usable.
>
> Commerce attestors are typically transaction-scoped: their
> assertions materialise in the context of a payment authorisation
> rather than as standing identity tokens. A service that accepts a
> commerce attestor identifier should expect to consume the assertion
> in the same request flow that carries its payment context, not as
> a presentable token issued ahead of any commerce.
>
> The set of accepted attestors is declared per-service in
> `billing.accepted_attestors`. Conforming services MUST validate the
> attestation against the attestor's published verification key (for
> asymmetric attestors) or shared secret (for HMAC attestors).

### Knock-on edits to AFAP-0006

AFAP-0006's "Replacement text for §10.3 first paragraph and list"
updates the same bulleted list. If both AFAPs are accepted in either
order, the §10.3 list must compose. Update AFAP-0006's proposed
replacement text to:

- Drop `aws-iam-agent` from the platform attestors line.
- Replace `stripe-projects` with `visa-trusted-agent` in the commerce
  attestors line.

The bootstrap-attestor class addition (the substantive change in
AFAP-0006) is preserved unchanged. The two AFAPs then compose into a
single §10.3 with four classes (bootstrap, platform, commerce, HMAC)
and the refreshed identifiers. The informative paragraphs added by
this AFAP follow the bulleted list in either composition order.

## Compatibility

**Wire-tightening on names; additive on the new identifier.**

- Removing `aws-iam-agent` and `stripe-projects`: no known deployed
  consumer. Neither identifier has a viable verification
  implementation against any AWS- or Stripe-issued externally
  consumable token. Any service that declared either in
  `billing.accepted_attestors` was already non-conforming under the
  existing §10.3 "MUST validate against published verification key"
  clause.
- Adding `visa-trusted-agent`: pure additive reservation. No service
  is required to accept it; services that do gain a documented
  identifier for the Visa Trusted Agent Protocol assertion.
- Informative paragraphs: non-normative; cannot break conformance.
- Reference implementations (TS SDK, CLI): no code change required.
  The identifiers were strings in spec prose, not in implementation
  code.

## Security and privacy considerations

**Reduced false-affordance surface.** Removing two identifiers that
point at no verifiable token reduces the risk of a service operator
declaring `aws-iam-agent` or `stripe-projects` in `accepted_attestors`
under the impression that the protocol provides a working verification
path, then either (a) shipping a broken signup gate or (b) implementing
an unverifiable shortcut that defeats the attestation's security
purpose.

**Adding `visa-trusted-agent` introduces no new attack surface beyond
Visa's existing protocol.** Verification is offline against Visa's
published JWKS; the trust anchor is Visa's network. Services that
accept this identifier inherit Visa's operational and revocation
practices for that JWKS, identical to how services accepting
`microsoft-entra-agent-id` inherit Microsoft's.

**Informative caveats reduce confused-deputy risk.** Authors of
conforming services who do not read between the lines of §10 may
treat all listed identifiers as substitutable. Calling out that
platform attestors require tenant federation, and that commerce
attestors are transaction-shaped, prevents misuse where a service
expects a standing token from an attestor that does not produce one.

**No change to §10.2 (token shape), §10.4 (lifetime), or §9.2
(`attested_only` mode).** This AFAP is identifier-level cleanup; the
surrounding §10 mechanics are untouched.

## Alternatives considered

- **Rename `aws-iam-agent` to `aws-bedrock-agentcore` and leave it
  on the list.** Rejected. The name correction would still leave the
  verification problem: AgentCore's workload access token is
  explicitly first-party. There is no AWS-issued token an arbitrary
  internet service can verify. Reserving an identifier that cannot
  fulfil §10.3's "MUST validate" clause is worse than not reserving
  it.
- **Rename `stripe-projects` to `stripe-agentic-commerce` and leave
  it on the list.** Rejected for the same reason. Stripe's identity
  primitives are platform-internal across all named products (SPT,
  Issuing for Agents, Link, guardrails). Renaming changes only the
  label; the verification path remains absent.
- **Also remove `google-cloud-agent-identity`.** Considered. The
  current Google product issues SVIDs against a trust domain
  (`agents.global.org-{ORG_ID}.system.id.goog`) but has not published
  a public federation endpoint. The argument for removal mirrors the
  AWS/Stripe one. The argument for retention: SPIFFE federation is a
  documented roadmap item; the identifier reservation is
  forward-looking. Lean retention with the platform-attestor caveat
  handles the operational gap. Revisit if Google ships a federation
  endpoint and the audience-binding story remains incompatible.
- **Add a new "proof-of-personhood" class with `world-id` (Tools for
  Humanity).** Considered. World AgentKit (March 2026) ships the
  strongest "human behind this agent" signal in the surveyed
  landscape. Rejected for v0.1 minimum scope: it would introduce a
  fourth class of attestor and open a debate about whether other
  proof-of-personhood schemes deserve reservations. Better handled in
  its own AFAP once the class is worth defining.
- **Rename `fido-agent-payments` → `fido-ap2` to match the protocol's
  own naming.** Considered. The Agent Payments Protocol is widely
  referred to as AP2 in 2026 (donated to FIDO Alliance April 2026).
  Rejected as out of minimum scope: the current identifier is a
  recognisable English-language name and the rename would create
  churn against an identifier that has no known interop issues.
  Cosmetic only; can land later if a deployed user requests it.
- **Defer the cleanup to v0.2.** Rejected. The window where
  reserved-identifier churn is cheapest is the working-draft phase.
  Removing `aws-iam-agent` and `stripe-projects` after v0.1
  stabilises requires a deprecation cycle this AFAP does not
  currently need.

## References

- §10.3 of [`../spec/core.md`](../spec/core.md)
- AFAP-0006: AFAuth bootstrap attestor —
  [`0006-afauth-bootstrap-attestor.md`](0006-afauth-bootstrap-attestor.md)
- Visa Trusted Agent Protocol —
  <https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications>
- Amazon Bedrock AgentCore Identity (workload access token semantics)
  — <https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html>
- Stripe Agentic Commerce overview —
  <https://stripe.com/use-cases/agentic-commerce>
- [RFC 9421] HTTP Message Signatures
- 2026 landscape survey informing this refresh —
  <https://artidrop.ai/a/SZdaHUIaL7>
