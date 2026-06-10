# AFAP-0008: Trust attestor as OpenID Provider ("Sign in with AFAuth")

**Status:** Accepted
**Author:** Editor
**Filed:** 2026-06-10
**Accepted:** 2026-06-10 (§10.8 inserted with normative OIDC-IdP, ID-Token,
  client-registration, and issuer-canonicalization requirements; §10.4.4
  cross-referenced; §15.1 references extended; composes with AFAP-0006)
**Affects:** core.md §10 (adds §10.8; note in §10.4.4), §15

## Summary

Permit the trust attestor (`afauth-trust`, AFAP-0006) to additionally operate
as an OpenID Provider so that a *human* can sign in to a service and land in the
account their *agent* already created — "Sign in with AFAuth", the agent-first
analogue of "Sign in with Google".

The mechanism reuses machinery AFAuth already has. An account is keyed on the
pairwise principal `(iss, sub_h)` (§10.4.4), which is exactly an OIDC
`(issuer, subject)` pair. The attestor mints an OIDC ID Token whose `sub` is the
same `sub_h` it would place in an attestation for that human and service, so the
agent's attested signup and the human's interactive sign-in converge on one
account.

This AFAP pins the wire shape (endpoints, ID-Token claims, client registration)
and the single normative obligation it places on consuming services (issuer
canonicalization). It does not specify the attestor's human-authentication
ceremony or any service's post-sign-in access policy.

## Motivation

AFAP-0006 and §10.4.4 already let a service treat several of a human's agents as
one account, keyed on `(iss, sub_h)`. What that model could not yet express is
the human walking up to the *same* service in a browser and being recognised as
the principal behind that account. Without it, a human who wants to see or
manage what their agent did must go through the §7 claim ceremony — an
*agent-initiated* invitation. There is no *human-initiated* "just sign me in"
path, even though the service already holds a stable, pairwise handle for that
human.

The gap is awkward precisely because the account key is *already* an OIDC
subject. `sub_h` is a per-(principal, service) pairwise pseudonym (§10.4.2);
`(iss, sub_h)` is `(issuer, subject)`. The only missing piece is an issuer
endpoint: something that, after authenticating the human, returns a signed token
carrying that `sub_h`. The trust attestor is the natural home — it already holds
the human↔principal binding (§10.3.1), already publishes a JWKs document that
consuming services trust (§10.3.1), and already derives `sub_h` (§10.4.3).
Standing it up as an OpenID Provider closes the loop with no new trust root and
no new cryptographic primitive.

## Specification

### New subsection §10.8 — Human sign-in via the trust attestor (OpenID Provider)

Insert immediately after §10.7:

> ### 10.8 Human sign-in via the trust attestor (OpenID Provider)
>
> §10.1–§10.7 gate an *agent's* signed requests. This section defines how a
> *human* signs in to a service and lands in the account their agent already
> created — "Sign in with AFAuth", the agent-first analogue of "Sign in with
> Google". It builds entirely on the pairwise principal `(iss, sub_h)` of §10.4
> and adds no new trust root.
>
> The trust attestor (§10.3.1) MAY additionally operate as an OpenID Provider
> [OIDC-Core]. The requirements below apply when it does. An attestor that does
> not offer human sign-in is unaffected.
>
> #### 10.8.1 Endpoints and flow
>
> - The attestor MUST publish an OpenID Provider configuration document
>   [OIDC-Discovery] at `https://trust.afauth.org/.well-known/openid-configuration`,
>   advertising at minimum its `issuer`, `authorization_endpoint`,
>   `token_endpoint`, and `jwks_uri`.
> - The advertised `issuer` MUST be the URL `https://trust.afauth.org`. This is
>   the attestor's OIDC issuer identifier; it is a distinct syntactic form from
>   the bare-string attestation `iss` of §10.3.1, and §10.8.4 governs how a
>   service reconciles the two.
> - The attestor MUST implement the Authorization Code flow with PKCE [RFC7636]
>   using the `S256` code-challenge method. The implicit and hybrid flows MUST
>   NOT be offered. Authorization codes MUST be single-use and short-lived.
> - The `jwks_uri` SHOULD be the same JWKs document used for attestation
>   verification (§10.3.1), so a consuming service verifies ID Tokens with keys
>   it already trusts.
> - The human authenticates to the attestor as the same human-controlled
>   account that backs the agent binding of §10.3.1. The attestor returns an
>   authorization code to the service's registered redirect URI, which the
>   service exchanges at the token endpoint for an ID Token.
>
> #### 10.8.2 ID Token claims
>
> The ID Token MUST conform to [OIDC-Core] and additionally:
>
> - `iss` MUST be `https://trust.afauth.org`.
> - `aud` MUST be the relying service's `service_did`, established at client
>   registration (§10.8.3). A service MUST reject an ID Token whose `aud` does
>   not match its own `service_did`.
> - `sub` MUST be the pairwise pseudonym `sub_h` that the attestor derives for
>   `(principal, aud)` per §10.4 — that is, **the identical value the attestor
>   places in the `sub_h` claim of an attestation issued to the same service for
>   the same human.** This equality is the convergence guarantee: the agent's
>   attested signup and the human's sign-in resolve to one `(iss, sub_h)`.
> - `exp` MUST be in the future at verification; the attestor SHOULD keep the ID
>   Token short-lived.
> - `nonce` MUST be echoed when the service supplied one at the authorization
>   endpoint.
>
> The ID Token MUST NOT carry personal data, consistent with §10.3.1. `sub` is
> the pairwise pseudonym, never an email, name, or other identifier.
>
> #### 10.8.3 Client registration
>
> A service that offers human sign-in registers with the attestor as an OIDC
> client. The registration MUST bind, at minimum, a `client_id`, the service's
> `service_did`, and an allowlist of exact `redirect_uris`. The registered
> `service_did` MUST equal the value the service uses as its `aud` / `service_did`
> for attestation (§10.2, §4.3), because that value is the audience input to the
> §10.4.3 `sub_h` derivation; a mismatch yields a different `sub`, and the human
> lands in a different (empty) account. The attestor MUST reject an authorization
> request whose `redirect_uri` is not in the registered allowlist, before issuing
> any code.
>
> #### 10.8.4 Issuer canonicalization (convergence requirement)
>
> A service that groups a human's agents into one account keyed on
> `(iss, sub_h)` (§10.4.4) and also offers human sign-in MUST treat the
> bare-string attestation issuer `afauth-trust` (§10.3.1) and the OIDC issuer URL
> `https://trust.afauth.org` as **the same issuer identity** when computing the
> account key. Equivalently, the service MUST canonicalize both forms to a single
> issuer identifier — RECOMMENDED: the URL `https://trust.afauth.org` — before
> lookup. A service that skips this step keys the agent's attested signup and the
> human's sign-in under two different `iss` values, so the human lands in a new,
> empty account instead of the one their agent created.
>
> #### 10.8.5 What sign-in does and does not do
>
> Signing in authenticates the human principal behind the account identified by
> `(iss, sub_h)`. What access a service grants on a successful sign-in is local
> policy, consistent with §10 throughout. Sign-in is authentication, not
> ownership transfer: it does not by itself perform the §7 claim that binds an
> `owner` and raises the §7.5 owner-binding floor. A service MAY treat a first
> successful human sign-in as sufficient to expose the agent-created account to
> its human principal, and MAY separately run the §7 claim ceremony to establish
> a recoverable owner binding.

### Cross-reference in §10.4.4

Append to the §10.4.4 grouping paragraph a pointer to §10.8: when the same
attestor also issues OIDC ID Tokens for human sign-in, the service MUST treat
the attestation issuer and the OIDC issuer URL as one issuer identity when
keying the account (§10.8.4).

### References (§15.1)

Add normative references for [OIDC-Core] and [RFC7636] (PKCE).

## Compatibility

**Wire-additive, no breaking change.**

- No change to the agent attestation path (§10.1–§10.7) or to any agent-facing
  surface. An agent that never signs a human in is unaffected.
- No change to the `/.well-known/afauth` discovery document. Human sign-in is a
  service-local product feature layered on standard OIDC and needs no new AFAuth
  discovery field; the attestor advertises its capability through the standard
  OIDC discovery document at its own well-known URI.
- The attestation `iss` remains the bare string `afauth-trust` (§10.3.1,
  unchanged). Services that adopted §10.4.4 grouping before this AFAP and do not
  offer human sign-in need do nothing. Services that *do* offer sign-in MUST
  canonicalize the two issuer forms (§10.8.4) — a one-line mapping, not a schema
  change.
- No new error code. An ID Token that fails verification is rejected through the
  service's existing 401 surface; the protocol takes no opinion on the UX for
  "no account yet".

## Security and privacy considerations

**Convergence is the feature; canonicalization is the failure mode.** The one
new way to get this wrong is to key human sign-in under `iss = https://trust.afauth.org`
while the agent's attested signup was keyed under `iss = afauth-trust`. The human
then lands in a fresh, empty account rather than the one their agent built. This
is a correctness bug, not a security hole — but it is silent and confusing, so
§10.8.4 makes the canonicalization a normative requirement rather than a footnote.

**Audience binding (unchanged from §10.3.1).** The ID Token `aud` is the relying
service's `service_did`; a service MUST reject a token minted for another
audience, so an ID Token issued for service A cannot be replayed at service B —
the same redirection defence §10.3.1 applies to attestations.

**Key theft does not forge sign-in.** An ID Token carrying a given `sub_h` can
only be minted by the attestor after it authenticates the human, never by holding
an agent's `did:key`. So a stolen agent key — which can already operate the
agent's account (the §8 threat model, addressed by rotation and revoke) — cannot
*additionally* impersonate the human's sign-in. Conversely, the ID Token is not
an owner-binding credential: signing in authenticates the principal behind the
`(iss, sub_h)` account but does not perform a §7 claim or raise the §7.5 floor
(§10.8.5). Services that want a recoverable human owner still run §7.

**Pairwise property is now load-bearing for an interactive flow.** Because `sub`
is the §10.4 pairwise pseudonym, two colluding services still cannot correlate
the same human across them from the ID Token — the guarantee §10.4 gives for
attestations now also covers sign-in. The attestor MUST NOT place PII in the ID
Token (§10.8.2), preserving §10.3.1's constraint.

**PKCE and single-use codes.** Mandating Authorization Code + PKCE (`S256`) with
single-use, short-lived codes defends the public-client redirect against code
interception; the implicit and hybrid flows are disallowed to keep tokens out of
redirect URLs.

## Alternatives considered

- **Use a sign-in issuer equal to the attestation `iss` (`afauth-trust`).**
  Rejected. OIDC requires the issuer to be a URL that hosts the discovery
  document ([OIDC-Discovery] §3); a bare string is not dereferenceable.
  Reconciling the two forms service-side (§10.8.4) is cheaper than violating
  OIDC.
- **Carry the human's email / name in the ID Token (classic OIDC profile
  claims).** Rejected. It breaks §10.3.1's no-PII constraint and §10.4's
  pairwise property. A service that needs a verified email runs the §7 claim,
  which is built for exactly that and is consent-gated.
- **Make sign-in perform the §7 claim implicitly (first sign-in == owner
  binding).** Rejected at the spec level; left to local policy (§10.8.5).
  Conflating authentication with ownership would silently raise the §7.5
  owner-binding floor on a flow the agent never initiated. Services that want
  that behaviour can opt into it, but it must not be mandatory.
- **Add an AFAuth discovery field advertising "human sign-in supported".**
  Rejected as unnecessary protocol surface. Sign-in is a property of the
  *attestor* (discoverable via standard OIDC), and whether a given service shows
  a button is a product choice with no interop consequence.
- **Fold this into AFAP-0006.** Rejected. 0006 is Accepted and deliberately
  narrow ("issue a short-lived, audience-bound JWT"). Human sign-in adds
  endpoints and an interactive flow; a separate AFAP keeps the history
  reviewable.

## References

- §7, §10.3.1, §10.4, §10.4.4, §10.5 of [`../spec/core.md`](../spec/core.md)
- [AFAP-0006](0006-afauth-trust-attestor.md) — the trust attestor this AFAP extends
- [RFC7636] Sakimura, N., Ed., Bradley, J., and N. Agarwal, "Proof Key for Code
  Exchange by OAuth Public Clients", RFC 7636, September 2015.
- [OIDC-Core] Sakimura, N., Bradley, J., Jones, M. B., de Medeiros, B., and C.
  Mortimore, "OpenID Connect Core 1.0", OpenID Foundation, November 2014.
- [OIDC-Discovery] "OpenID Connect Discovery 1.0", OpenID Foundation.
- [RFC7519] "JSON Web Token (JWT)".
