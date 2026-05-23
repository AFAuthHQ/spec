# AFAP-0003: Non-normative service directory at afauth.org

**Status:** Draft
**Author:** Editor
**Filed:** 2026-05-23
**Affects:** No changes to `spec/core.md`. Adds `spec/directory.md` (informational) and `spec/schemas/listing.json`.

## Summary

Define a non-normative public **service directory** — a list of services
that have voluntarily announced AFAuth support — operated at
`https://afauth.org/registry` and mirrorable by anyone. The directory's
sole purpose is announcement and cold-start discovery for early
adopters; it imposes no requirements on either agents or services and
introduces no new fields on the `/.well-known/afauth` document.

Membership is **opt-in**, **self-serve via the protocol's own signature
scheme**, and **independent of conformance**: a listing means a service
has claimed AFAuth support, not that it has been audited.

This AFAP is **informational**, in IETF terms — `spec/core.md` does not
change. It defines a community convention that the protocol's ecosystem
may use without requiring any implementation to participate.

## Motivation

§1.3 of `core.md` puts service discovery — i.e., the question "what
URL should the agent probe?" — explicitly out of scope. That decision
is correct for the protocol: a normative directory would reintroduce
the centralisation that the well-known + DID model was designed to
avoid.

But the carve-out leaves a real gap **for service operators, not
agents**: a service that ships AFAuth support today has no way to
announce that fact to a broader audience than its existing users.
Crawlers will eventually find it via well-known probing; ecosystem
flywheels can take years to ignite without a coordination layer.

The MCP working group hit the same problem and shipped an opt-in
registry at `registry.modelcontextprotocol.io` (see References). Their
experience — both the working parts and the painful ones — is the
strongest available evidence on what such a directory should and
shouldn't look like. The design below borrows liberally and corrects
known pain points.

The key constraint: **the directory must not be load-bearing for the
protocol.** If `afauth.org` disappeared tomorrow, every conforming
agent and service must continue working unchanged. This AFAP discharges
that constraint by keeping the directory entirely outside `core.md`.

## Specification

### D.1 Status and scope

This document is informational. It does not amend `core.md`. A
conforming agent or service has no obligation to interact with any
directory. The directory describes a convention for the
`afauth.org`-hosted registry and any mirror or fork that wishes to
interoperate with it.

### D.2 Listing record

Each listing is a JSON object with the following shape:

```json
{
  "service_did":     "did:web:api.example.com",
  "discovery_url":   "https://api.example.com/.well-known/afauth",
  "discovery_doc":   { /* cached copy of /.well-known/afauth */ },
  "fetched_at":      "2026-05-23T14:00:00Z",
  "first_listed_at": "2026-04-01T09:12:33Z",
  "status":          "active",
  "tags":            ["productivity", "storage"],
  "title":           "Example Photo Storage",
  "description":     "AFAuth-supported photo storage for agents.",
  "_meta":           { }
}
```

The full JSON Schema is provided alongside this AFAP at
[`../schemas/listing.json`](../schemas/listing.json).

**Required fields:** `service_did`, `discovery_url`, `discovery_doc`,
`fetched_at`, `first_listed_at`, `status`.

**`discovery_doc`** is a cached snapshot taken at `fetched_at`.
Consumers that need to act on `endpoints`, `billing`, or
`accepted_attestors` (rather than merely display the listing) SHOULD
re-fetch the live `/.well-known/afauth` document from `discovery_url`
before doing so; the cached copy may lag the live document by up to
the directory's revalidation interval.

**`status`** is one of:
- `active` — discovery doc fetched successfully on the last probe and
  validates against `schemas/well-known.json`.
- `stale` — recent probes failed or the discovery doc no longer
  validates; retained for downstream mirror convergence.
- `deleted` — the controller of `service_did` requested removal.
  Retained (soft-delete) so mirrors converge.

**`_meta`** is a free-form object reserved for future extensions.
Federation conventions for `_meta` (namespacing, third-party
annotations, scan results) are deliberately not specified in this
version and will be defined in a follow-up AFAP if and when there are
aggregators that need them.

### D.3 Identity model

A listing is **bound to the `service_did` already declared in the
discovery document.** AFAuth's existing DID model is the only namespace
the directory needs; reverse-DNS namespacing (as in MCP) is not adopted
because it would parallel the DID layer without adding security.

Consequences:

- A `did:web:host` listing's authority is anchored in DNS + TLS for
  `host` — the same anchor used elsewhere in the protocol. Claiming
  `did:web:acme.example.com` requires control of `acme.example.com`,
  full stop.
- Listings keyed by `did:key:` are accepted without restriction. The
  signed-submission protocol (D.4) is sufficient: an attacker
  attempting to impersonate `did:key:zA` needs either the controller's
  private key or control of the host serving the discovery document —
  the same threat surface that protects `did:web` listings. The UX
  difference remains: `did:key` carries no domain anchor
  (`core.md` §4.3), so a consumer browsing a listing cannot infer the
  operating organisation from the DID alone. Browse interfaces
  presenting listings MUST render `did:key:` entries with a visible
  "no domain anchor" indicator and prominently display the host
  derived from `discovery_url`.
- Conflicts cannot arise: two services cannot legitimately claim the
  same `service_did`, because the DID resolves to at most one key set.

### D.4 Listing protocol

A service controller submits a listing by making an **AFAuth-signed**
HTTP request to the directory, using the same HTTP Message Signatures
scheme (`core.md` §5) the service uses with agents. This avoids a
parallel auth system (no GitHub OAuth, no DNS TXT challenge file) and
re-uses authority the service already has.

```http
POST /registry/v1/listings HTTP/1.1
Host: afauth.org
Content-Type: application/json
Signature-Input: sig1=("@method" "@target-uri" "content-digest");
                 created=1748005200;expires=1748005500;nonce="...";
                 keyid="did:web:api.example.com";alg="ed25519"
Signature: sig1=:...:

{
  "discovery_url": "https://api.example.com/.well-known/afauth",
  "title":         "Example Photo Storage",
  "description":   "AFAuth-supported photo storage for agents.",
  "tags":          ["productivity", "storage"]
}
```

The directory:

1. Resolves the DID in `keyid` (per `core.md` §5.2, `keyid` is the bare
   DID with no fragment).
2. Verifies the request signature against the resolved key.
3. Fetches `discovery_url` independently and validates against
   `schemas/well-known.json`.
4. Confirms that `discovery_doc.service_did` equals `keyid`.
5. On success, creates or updates the listing.

Removal and metadata updates use the same signed-request scheme
(`PATCH /registry/v1/listings/{service_did}`,
`DELETE /registry/v1/listings/{service_did}`).

The directory MUST honour signed key-rotation events. For `did:web`
listings, after the controller publishes a new verification method in
their DID document, subsequent signed requests against the rotated key
MUST be accepted; the directory re-resolves the DID document on
signature verification (`core.md` §3.1.2). `did:key` listings have no
in-place rotation, because the verification key is the identifier
(`core.md` §3.1.1, §8.1): rotating the key produces a new
`service_did` and therefore a new listing. The controller SHOULD
`DELETE` the old listing before `POST`ing a fresh one under the new
DID so consumers see a clean transition; `service_did` continuity
across `did:key` rotation is not provided.

### D.5 Read API

All read endpoints are unauthenticated, served over HTTPS with HSTS,
and rate-limited only against abuse.

| Endpoint | Purpose |
|---|---|
| `GET /registry/v1/listings` | Cursor-paginated list. Query params: `cursor`, `limit` (≤100), `search`, `tag`, `updated_since` (RFC 3339), `status`, `include_deleted`. |
| `GET /registry/v1/listings/{service_did}` | Single listing. |

Two endpoints is deliberately the entire v0 surface. Bulk-dump,
snapshot, history, and OpenAPI endpoints are non-breaking additions
that may be introduced in a follow-up AFAP once a consumer pattern
exists that the paginated list cannot serve; at the expected v0
scale (tens of listings), the paginated list is sufficient for
mirrors and aggregators that poll with `updated_since`.

### D.6 Conformance probes

Active conformance probing against listed services — running test
vectors, publishing per-listing pass/fail results, the directory
acting as a signing AFAuth agent (`did:web:afauth.org`), and the
attendant rate budget — is **out of scope for this AFAP** and is
tracked separately. The directory's only liveness signal in this
version is the discovery-document revalidation defined in §D.7.

When conformance probing is added in a future AFAP, the listing
record (§D.2) gains a `conformance` block; existing fields are
unchanged.

### D.7 Revalidation and soft-delete

The directory periodically (RECOMMENDED daily) re-fetches each
listing's `discovery_url`. A listing transitions to `stale` only after
**at least three consecutive revalidation failures** — a single
network blip or transient 5xx MUST NOT flip a healthy listing. After
a controller-configurable grace period (RECOMMENDED 30 days from the
first failure in the run that drove the listing to `stale`), the
directory MAY transition `stale` listings to `deleted`.

`deleted` records persist in the list response with
`status: "deleted"` (returned only when `include_deleted=true`) so
mirrors converge. Hard-erase is reserved for unlawful content.

The directory retains only the **current** `discovery_doc` snapshot
per listing in this version. Per-listing history, history-purge,
registry-wide daily snapshots, and snapshot-retention policy are
out of scope and may be added by a follow-up AFAP.

### D.8 Federation

The directory **is not the protocol's single source of truth.** Anyone
may host a directory implementing the same surface; agents and
aggregators may consume any directory or several. The schema lives in
`spec/schemas/listing.json` and is versioned alongside the spec.

Recommended federation patterns:

- **Mirrors**: clone the canonical dataset by polling
  `GET /registry/v1/listings` with `updated_since`, and serve
  identical content under their own domain.
- **Aggregators**: combine the canonical directory with their own
  curation, scan results, or editorial annotations. Conventions for
  representing third-party annotations on a listing are not specified
  in this version (see §D.2 `_meta`).
- **Private directories**: enterprises with internal-only AFAuth
  services run their own directory, never publishing to
  `afauth.org`. The same schema and signed-submission protocol apply.

### D.9 Operator and governance

AFAuthHQ operates `afauth.org/registry` in this version. A public
operator commitment at `https://afauth.org/registry/operator`
documents:

- Who has operational authority.
- The actions the operator MAY take unilaterally (routine moderation
  per D.10, infrastructure changes, schema-conformant data
  migrations).
- The actions the operator MUST NOT take unilaterally (delisting a
  service outside the published moderation policy, breaking-change
  schema amendments, censoring listings on ideological grounds).

The schema and signed-submission protocol are public; anyone may
mirror, fork, or run a private directory (see §D.8). Governance
evolution — a steering committee, donation to a neutral standards
home, multi-operator co-stewardship — will be addressed in a
follow-up AFAP once adoption warrants it. This AFAP does not commit
the project to a specific governance trajectory in advance of that
evidence.

### D.10 Take-down policy

The canonical directory's take-down policy (illegal content, malware,
spam, fraudulent claims) is published at
`https://afauth.org/registry/policy`. Operational decisions made by
the canonical directory do not bind mirrors or aggregators, which set
their own policies.

A service controller may withdraw a listing at any time by signing a
`DELETE` request (D.4). Withdrawn listings appear in
`GET /registry/v1/listings?include_deleted=true&updated_since=…` with
`status: "deleted"` so mirrors converge.

## Compatibility

**Wire-compatible.** No changes to `core.md`. No additions to the
`/.well-known/afauth` document. No new endpoints on services. No new
behaviour required of agents. A conforming v0.1 implementation is
unaware of the directory's existence.

The directory MAY be deprecated, replaced, or forked without affecting
protocol conformance.

## Security and privacy considerations

**Squatting and impersonation.** Because listings are bound to
`service_did` and the directory verifies a fresh signature from the
DID's current key against an independently-fetched discovery
document, a third party cannot list a service they do not control.
This is a strict improvement over MCP's reverse-DNS + GitHub OAuth
model, which conflates code-host identity with service authority.

**Stale or hostile listings.** A controller whose keys are compromised
can submit hostile listings (e.g., redirecting `discovery_url` to a
look-alike host). The directory MUST re-validate that
`discovery_doc.service_did` matches the listing's `service_did` on
every submission and re-probe; mismatches reject. Controllers with
rotated keys can re-claim listings via the §8 key-rotation flow.

**Listing as a tracking vector.** The directory's list endpoint
exposes every listed service. Services that do not wish to be in a
public directory simply do not list themselves; the well-known
mechanism continues to work for unlisted services.

**TLS as the only directory-integrity anchor in v0.1.** The directory's
own responses are protected by TLS. A future version MAY have the
directory sign its responses with a directory-DID; out of scope for
this AFAP.

**No collection of agent-side data.** The directory holds records
about *services*, not agents or accounts. No telemetry from agents
flows through the directory.

**Privacy of `discovery_doc` snapshots.** The directory caches the
current copy of each service's discovery document. In this version
only the current snapshot is retained per listing; if per-listing
history is added in a future AFAP, services should reassess what they
publish into the discovery document (notably `billing.accepted_attestors`,
`features`, and `endpoints` URLs, which can carry business or
architectural signal).

## Alternatives considered

- **No directory at all.** Rejected. Forecloses the cold-start
  flywheel for early adopters and concedes the discovery layer to
  third parties whose schemas the protocol does not control.

- **Static GitHub repo** (e.g., `awesome-afauth`). Considered.
  Lighter weight but provides no programmatic API, no conformance
  pings, no signed-submission identity guarantee. May still exist
  alongside; not mutually exclusive.

- **MCP-style hosted registry, modeled exactly on
  `registry.modelcontextprotocol.io`.** Considered. Rejected as a
  literal copy for two reasons: (1) AFAuth has DIDs, so reverse-DNS
  namespacing is redundant; (2) MCP's namespace-auth-only model is
  weaker than AFAuth's signed-submission model. This AFAP keeps
  MCP's soft-delete and `updated_since` patterns and replaces the
  identity model with DID-anchored signed submission.

- **Shipping bulk-dump, snapshots, per-listing history, OpenAPI, and
  conformance probes in v0.** Considered. Rejected: each is a
  non-breaking addition (new endpoint or optional field) with no
  current consumer. The registry will see tens, not thousands, of
  listings in its first phase; paginated list with `updated_since`
  serves every known v0 use case. A small, robust v0 that we can
  extend on evidence beats a speculative v0 we have to maintain
  speculatively. Each deferred item is named in §D.5, §D.6, §D.7,
  and §D.8 with a clear add-back path.

- **`directory` field in the discovery document** that points the
  agent at a known registry. Rejected. Couples the protocol to the
  directory and creates a normative dependency on whichever directory
  is named.

- **Fully peer-to-peer announcement** (e.g., a Nostr-style relay
  network). Considered. Higher resilience but very high operational
  complexity for v0.1's adoption stage. May be revisited as the
  ecosystem matures.

- **Commercial / for-profit registry.** Considered. Rejected for the
  canonical operator role; bias incentives undermine the trust the
  directory needs. Commercial aggregators on top of the public
  listings endpoint are welcome.

## References

- **MCP Registry**, Model Context Protocol working group.
  [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io),
  [github.com/modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry),
  [modelcontextprotocol.io/registry/about](https://modelcontextprotocol.io/registry/about).
- **MCP server.json schema**:
  `static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`.
- **MCP moderation policy**:
  `modelcontextprotocol.io/registry/moderation-policy`.
- §1.3, §4, §5, §8 of [`core.md`](../spec/core.md).
- [RFC 8615] Well-Known URIs.
- [RFC 9421] HTTP Message Signatures.
- [W3C-DID-WEB] DID method `did:web`.
