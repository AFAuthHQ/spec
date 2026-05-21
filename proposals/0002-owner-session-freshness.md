# AFAP-0002: Owner-session freshness floor for owner-binding operations

**Status:** Accepted
**Author:** Editor
**Filed:** 2026-05-21
**Accepted:** 2026-05-21
**Affects:** `spec/core.md` §7.5, §11.3; `vectors/errors/` (new fixture)
**Landed in:** §7.5 (freshness paragraph), §11.3 (reserved code listing + distinguishing clause), `vectors/errors/owner_session_too_stale.json`.

## Summary

Tighten §7.5 to require that an "owner-authenticated session"
authorising an owner-binding operation evidence a *recent*
authentication event — not merely a long-lived cookie. Add a new
reserved error code `owner_session_too_stale` (403 Forbidden) to
§11.3, distinct from the existing `owner_authentication_required`
(no session) and `owner_binding_blocked` (agent-signed request to
an owner-binding op).

This is **wire-additive**. Existing handlers continue to function;
the new error code is reserved for services that adopt the
freshness floor.

## Motivation

The §7.5 owner-binding floor is the second load-bearing invariant
in AFAuth's security argument. Today it says:

> *"An operation that modifies which credentials can authenticate as
> the owner MUST require an owner-authenticated session; the agent
> key alone MUST NOT authorize such an operation."*

The word **session** is undefined. In practice, services ship cookies
with TTLs of 7 to 30 days. The threat model that breaks: an attacker
pops the human's browser session (XSS on the dashboard, malicious
extension, shared device left logged in), opens the owner-binding
route — enrol additional credential, add recovery contact, link
federated identity — and submits. The protocol's invariant is
satisfied to the letter (a session is presented), but the §7.1
two-step verify guarantee that survives revocation under §8.4 has
been silently unwound.

The fix is to require that the session evidence a *recent* user
verification event before an owner-binding op commits. This is
exactly how Apple's iCloud Keychain, Google's Sensitive Account
Actions, and GitHub's `sudo` mode all gate destructive operations
today. AFAuth simply makes the requirement normative for the
owner-binding category.

## Specification

### Tightening of §7.5

After the existing normative paragraph, add:

> For an owner-authenticated session to authorize an owner-binding
> operation, the service MUST require evidence of a *fresh*
> authentication event satisfying the assurance bar from §12.3,
> performed within a service-defined freshness window measured at
> the moment of the operation. Implementations SHOULD use a
> window of 60 to 300 seconds.
>
> A session that is otherwise valid but does not evidence a fresh
> authentication event MUST cause the service to reject the
> owner-binding operation with `403 Forbidden` and the error code
> `owner_session_too_stale` (§11.3). The service SHOULD prompt the
> human to re-authenticate and resubmit; the rejection MUST NOT
> consume any rate-limit allowance attributable to the agent.

### Addition to §11.3 (Reserved error codes)

Add `owner_session_too_stale` to the reserved-code list with the
following clarification immediately after the existing distinction
between `owner_authentication_required` and `owner_binding_blocked`:

> `owner_session_too_stale` is returned with `403 Forbidden` when an
> owner-authenticated session is present but the most recent
> authentication event the session evidences predates the service's
> §7.5 freshness window. It is distinct from
> `owner_authentication_required` (no session at all) and from
> `owner_binding_blocked` (an agent-signed request to an
> owner-binding op).

### Addition to §C.5 (Error envelopes)

A new fixture documents the envelope shape for the new code,
analogous to the existing 17 fixtures. The fixture's `http_status`
is 403.

## Compatibility

**Wire-additive.** The new code is a reserved identifier in the
existing §11.1 envelope shape; clients that do not recognise it
treat it as an opaque `error.code` per the existing §11 contract.

**Conformance.** A service that ships v0.1 without the freshness
floor remains conformant against the AFAP-0001 baseline (§12.3 is
SHOULD, not MUST, for AAL2+). Adopting the freshness floor is a
strict tightening: it never increases the surface a verifier
accepts, only the surface a service rejects.

## Security and privacy considerations

**Closes the §7.5 takeover window.** A popped session no longer
silently authorises owner-binding ops. The attacker must also
present fresh UV — which on a phishing-resistant ceremony
(AFAP-0001) requires possession of the registered device.

**Side-channel: agent-signed operations are unaffected.** Agents
don't have owner sessions; §7.5 has always blocked them with
`owner_binding_blocked` (403). This AFAP only refines the human
side.

**No rate-limit amplification.** The mandate that
`owner_session_too_stale` rejections MUST NOT consume the agent's
rate-limit allowance prevents an attacker who controls the agent
key from forcing the human into a re-authentication loop and
exhausting their `unclaimed_rate_limit_per_hour` budget by proxy.

## Alternatives considered

- **Mandate a specific mechanism (WebAuthn UV).** Rejected. The
  freshness check is between human and service, not on the
  agent↔service wire. Specifying the mechanism is implementation
  prescription that doesn't match AFAuth's "service-defined
  ceremony" principle. The recommendation in §12.3 (AFAP-0001) is
  the right place for mechanism guidance.
- **Rely on short session TTLs alone.** Rejected. A 30-minute TTL
  still gives an attacker a 30-minute window after a popped
  session. The freshness check captures the **most recent
  authentication event**, which is independent of session
  expiry — and the recommended 60–300s window is much shorter
  than any reasonable session TTL.
- **Leave §7.5 silent.** Rejected. The current text's reference to
  an undefined "session" is the largest unverifiable claim in the
  protocol; absent this AFAP, §7.5 is documentation, not a
  testable invariant.

## References

- §7.5, §11.3, §12.3 of [`core.md`](../spec/core.md).
- AFAP-0001 (Phishing-resistant claim ceremony recommendation).
- [`vectors/errors/`](../vectors/errors/) — §C.5 envelope fixtures.
