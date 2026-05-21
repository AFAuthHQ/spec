# AFAP-0001: Phishing-resistant claim ceremony recommendation and WebAuthn interop for the `did` recipient

**Status:** Accepted
**Author:** Editor
**Filed:** 2026-05-21
**Accepted:** 2026-05-21
**Affects:** `spec/core.md` §7.4, §7.7.4, §12.3, Appendix B
**Landed in:** §7.7.4 (WebAuthn ceremony framing), §12.3 (AAL2+ recommendation paragraph), Appendix B.2.2 (passkey worked example), §15.1 ([WebAuthn-L3], [OIDC-MFA] references).

## Summary

Add a normative recommendation in §12.3 that services targeting NIST
AAL2 or higher SHOULD use a phishing-resistant §7.4 claim ceremony,
naming WebAuthn / passkeys and OIDC `acr=phishing-resistant` as the
canonical implementations. Tighten §7.7.4 to make WebAuthn's
`navigator.credentials.get(publicKey: …)` the canonical
interoperability point for the `did` recipient's challenge-response.
Refresh Appendix B with a worked passkey ceremony alongside the
existing magic-link example.

This is **additive and wire-compatible** — magic-link-based ceremonies
continue to satisfy the spec for services that accept AAL1 risk; the
new normative text tells implementers when to climb higher.

## Motivation

The §7.1 two-step verify invariant is the protocol's distinctive
security claim: *"a stolen agent key cannot, by itself, redirect
ownership."* This invariant is enforced at the §7.4 boundary: the
claim ceremony binds an authenticated human identity to
`pending_recipient` before transitioning the account to `CLAIMED`.

The strength of the invariant therefore equals the strength of the
ceremony the service chooses. Today's Appendix B canonical example
is an email magic link, which:

- Is classified as **AAL1** by [NIST SP 800-63B] — the lowest assurance level.
- Is **phishable via adversary-in-the-middle** — a reverse-proxy on
  the claim-page URL can capture the token at the moment of redemption.
- May be **prefetched by email scanners**, security gateways, or
  preview generators, which can race-consume the token before the
  human clicks.
- Is **inheritable from email-account takeover** — if the attacker
  controls the mailbox (via credential stuffing on the IdP, SIM swap
  on a recovery factor, etc.), they can redirect the entire claim.

Services that take all of these risks SHOULD have a stronger default
available. WebAuthn / passkeys provide:

- **Origin binding at the cryptographic layer.** The credential refuses
  to sign for any RP ID other than the one it was registered against,
  so AitM phishing fails at the protocol level rather than at the
  user's judgement.
- **Per-ceremony user verification.** A UV gesture (biometric, PIN,
  or device unlock) is fresh evidence of human presence, not a
  long-lived cookie.
- **Device attestation.** AAGUID / MDS metadata lets services constrain
  which authenticator classes they accept (e.g., reject roaming
  authenticators with weak attestation).

The current spec leaves all of this to "service-defined" without
guidance. AFAP-0001 fixes that without removing the magic-link
fallback.

## Specification

### Addition to §12.3 (Claim ceremony strength)

After the existing paragraphs:

> Implementations SHOULD select a §7.4 claim ceremony whose
> assurance level (per [NIST SP 800-63B]) is commensurate with the
> value of the underlying account. Services targeting AAL2 or higher
> SHOULD use a phishing-resistant ceremony — canonical examples are
> WebAuthn-bound credentials per [WebAuthn-L3] (with required user
> verification) and OIDC flows that yield an `acr` value of
> `phishing-resistant` per [OIDC-MFA].
>
> A magic link delivered to an email address is AAL1 and remains
> the simplest interoperable default for the `email` recipient type
> (§7.7.1); services that accept this trade-off MUST document the
> assurance level in their claim-page user experience so the
> claimant can decide whether to enroll a stronger credential
> before completing the ceremony.

### Tightening of §7.7.4 (`did` recipient)

After the existing "Verification ceremony" paragraph, add:

> Where the DID's verification method exposes a public key compatible
> with [WebAuthn-L3] (P-256, RS256, EdDSA), the canonical ceremony
> framing is a `navigator.credentials.get(publicKey: PublicKeyCredentialRequestOptions)`
> call whose `challenge` is the service-issued freshness nonce, whose
> `allowCredentials` references the DID's verification method, and
> whose `userVerification` is `"required"`. Implementations that adopt
> this framing inherit phishing resistance and per-ceremony UV without
> additional protocol surface.

### Refreshed Appendix B

Add a sibling section "Passkey-based claim ceremony" next to the
existing email magic-link example. Both remain valid; the passkey
section becomes the AAL2+ recommended pattern.

## Compatibility

**Wire-compatible.** No new headers, no new endpoints, no changes
to existing fields. Services that ship a magic-link ceremony today
remain conformant.

**Conformance probe impact.** A future probe in
[`spec/conformance.md`](../spec/conformance.md) MAY check the
ceremony assurance level a service self-declares (e.g., a new
optional `discovery.claim_strength` field — out of scope for this
AFAP, deferred to a follow-on).

## Security and privacy considerations

**Strengthens §7.1.** The two-step verify invariant becomes
operationally meaningful at the default rather than only in theory.
A stolen agent key on a service that follows AFAP-0001's AAL2+
recommendation cannot complete the claim ceremony without the
human's UV gesture on a registered device.

**No new privacy attack surface.** The recommendation is about
ceremony strength, not identifier shape — cross-service linkability
(§13.1) is unaffected.

**Bootstrap caveat.** First-time human users of a service must still
enrol a passkey, and that enrolment requires some prior auth event.
This AFAP does not specify how passkey enrolment bootstraps; it
recommends the steady-state default once enrolment exists.

## Alternatives considered

- **Mandate WebAuthn universally.** Rejected. The bootstrap case
  ("the user has no passkey yet") and the long tail of devices
  without WebAuthn support would break interop. The recommendation
  must remain a SHOULD, not a MUST.
- **Leave §12.3 silent and update only Appendix B.** Rejected.
  Implementers read the normative text, not the worked examples;
  Appendix B alone fails to direct implementers toward the strong
  default.
- **Specify only the `did` ceremony.** Rejected. The §12.3
  recommendation applies regardless of recipient type — an `email`
  recipient backed by an IdP that supports passkey login satisfies
  the recommendation too.

## References

- [NIST SP 800-63B] — Digital Identity Guidelines, Authentication and Lifecycle Management.
- [WebAuthn-L3] — W3C Web Authentication: An API for accessing Public Key Credentials Level 3.
- [OIDC-MFA] — OpenID Connect MFA / `acr` values registry.
- §7.1, §7.4, §7.7.4, §12.3 of [`core.md`](../spec/core.md).
