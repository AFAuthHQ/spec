# AFAP-0002: Non-normative service directory at afauth.org

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
scheme**, **publicly downloadable in bulk**, and **independent of
conformance**: a listing means a service has claimed AFAuth support, not
that it has been audited.

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
  "conformance": {
    "harness_version":  "0.1.0",
    "last_run":         "2026-05-23T14:00:00Z",
    "vectors_passing":  78,
    "vectors_total":    78,
    "report_url":       "https://afauth.org/registry/conformance/did:web:api.example.com/2026-05-23.json"
  },
  "_meta": { }
}
```

The full JSON Schema is provided alongside this AFAP at
[`../schemas/listing.json`](../schemas/listing.json).

**Required fields:** `service_did`, `discovery_url`, `discovery_doc`,
`fetched_at`, `first_listed_at`, `status`.

**`status`** is one of:
- `active` — discovery doc fetched successfully on the last probe and
  validates against `schemas/well-known.json`.
- `stale` — last probe failed or the discovery doc no longer validates;
  retained for downstream mirror convergence.
- `deleted` — the controller of `service_did` requested removal.
  Retained (soft-delete) so mirrors converge.

**`_meta`** is a free-form, reverse-DNS-namespaced object for
non-normative annotations (security scan results, third-party ratings,
editorial notes). Borrowed from MCP's pattern. Members under
`afauth.org/...` keys are reserved for the canonical directory; mirrors
and aggregators MUST use their own DNS-anchored prefix.

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
                 keyid="did:web:api.example.com#key-1";alg="ed25519"
Signature: sig1=:...:

{
  "discovery_url": "https://api.example.com/.well-known/afauth",
  "title":         "Example Photo Storage",
  "description":   "AFAuth-supported photo storage for agents.",
  "tags":          ["productivity", "storage"]
}
```

The directory:

1. Resolves `keyid`'s DID document.
2. Verifies the request signature against the resolved key.
3. Fetches `discovery_url` independently and validates against
   `schemas/well-known.json`.
4. Confirms that `discovery_doc.service_did` matches the DID derived
   from `keyid`.
5. On success, creates or updates the listing.

Removal and metadata updates use the same signed-request scheme
(`PATCH /registry/v1/listings/{service_did}`,
`DELETE /registry/v1/listings/{service_did}`).

The directory MUST honour signed key-rotation events: after a
controller publishes a new verification method in their DID document
(or rotates a `did:key` via `endpoints.key_rotation`), subsequent
signed requests against the rotated key MUST be accepted.

### D.5 Read API

All read endpoints are unauthenticated, served over HTTPS with HSTS,
and rate-limited only against abuse.

| Endpoint | Purpose |
|---|---|
| `GET /registry/v1/listings` | Cursor-paginated list. Query params: `cursor`, `limit` (≤100), `search`, `tag`, `updated_since` (RFC 3339), `status`, `include_deleted`. |
| `GET /registry/v1/listings/{service_did}` | Single listing. |
| `GET /registry/v1/listings/{service_did}/history` | Past discovery-doc snapshots. |
| `GET /registry/v1/dump.json` | **Full dataset, single response.** No pagination. |
| `GET /registry/v1/dump.json.gz` | Gzipped equivalent. |
| `GET /registry/v1/snapshots/{YYYY-MM-DD}.json.gz` | Daily snapshot, immutable. |
| `GET /registry/v1/openapi.yaml` | The OpenAPI 3.1 description of this surface. |

The **bulk-dump endpoints are the first-class consumption pattern,**
not the paginated list. Aggregators, mirrors, and offline tools are
expected to download `dump.json.gz` daily and apply deltas via
`updated_since`. This corrects MCP's most-cited operational pain point
(forced pagination of ~8 k entries with 20–25 s tail latency).

Snapshots are content-addressable by date; once published, a snapshot
URL is immutable. This allows mirrors to verify they hold the same
data the canonical directory served on a given day without trusting
the directory's `updated_since` stream.

### D.6 Conformance probes

The directory MAY run the `spec/harness/` test vectors against each
listed service on a regular cadence and publish results in the
listing's `conformance` block. Conformance status is **advisory** —
listing eligibility does not depend on it. A service that fails some
vectors remains listed with `vectors_passing < vectors_total`; this is
deliberately distinct from `status: stale` (which means the discovery
doc itself didn't fetch or validate).

Probe artefacts are published at the URL given in
`conformance.report_url` so consumers can verify the result
independently.

#### D.6.1 Probe identity

The canonical directory has its own AFAuth identity,
`did:web:afauth.org`, with a DID document served at
`https://afauth.org/.well-known/did.json`. The directory uses this
identity to interact with listed services symmetrically — it
participates in the protocol it indexes.

- **Probes against public well-known endpoints** (GET
  `/.well-known/afauth`, GET `/.well-known/did.json`) are
  unauthenticated and carry
  `User-Agent: AFAuth-Registry-Probe/<version> (+https://afauth.org/registry/probe)`.
- **Probes that exercise authenticated endpoints** (harness vectors
  that POST signed requests per `core.md` §5) are signed by
  `did:web:afauth.org`. From the service's perspective, the directory
  is a regular AFAuth agent; signed probes produce an `UNCLAIMED`
  account whose `account_did` is derived from the directory's keys —
  the test artefact the harness already expects.
- **Outbound IP range** for the canonical directory is published at
  `https://afauth.org/registry/probe/ips.json` so operators who want
  stronger filtering than `User-Agent` matching may allowlist
  accordingly.

#### D.6.2 Rate budget

The canonical directory publishes its probe rate budget at
`https://afauth.org/registry/probe`. RECOMMENDED defaults:

- At most **1 discovery-doc revalidation per listing per 24 hours**.
- At most **1 full-harness run per listing per 7 days**.

Mirrors that probe independently SHOULD publish equivalent budgets
and SHOULD coordinate with the canonical directory's outbound schedule
where feasible to avoid duplicate load on service operators.

### D.7 Revalidation and soft-delete

The directory periodically (RECOMMENDED daily) re-fetches each
listing's `discovery_url`. On failure, the listing transitions to
`stale`. After a controller-configurable grace period (RECOMMENDED 30
days), the directory MAY transition `stale` listings to `deleted`.

`deleted` records persist in the dump with `status: "deleted"` so
mirrors converge. Hard-erase is reserved for unlawful content.

#### D.7.1 Per-listing history retention

Each successful revalidation produces a snapshot of the listing's
discovery document. The canonical directory retains the **last 12
successful snapshots per listing** (≈12 months at the recommended
daily cadence); older snapshots are discarded.

A controller may purge all per-listing history except the current
snapshot by submitting a signed request (same auth as D.4):

```http
POST /registry/v1/listings/{service_did}/history/purge
```

Daily registry snapshots already published under
`/registry/v1/snapshots/` were public when issued and are not
retracted by per-listing purge.

#### D.7.2 Registry snapshot retention

Daily snapshots (`/registry/v1/snapshots/{YYYY-MM-DD}.json.gz`) are
retained for **90 days**. Monthly aggregates derived from the daily
snapshots are retained for **24 months** to support ecosystem
analysis. Older aggregates MAY be discarded or moved to cold storage
at the operator's discretion.

#### D.7.3 Privacy-sensitive fields

The discovery document is already public, but historical retention
turns transient configuration into a durable record. Fields most
likely to carry business signal — notably `billing.accepted_attestors`
and the set of declared `features` — are documented at the operator
commitment page (D.9.1) so service operators understand what they are
publishing into history when they list.

### D.8 Federation

The directory **is not the protocol's single source of truth.** Anyone
may host a directory implementing the same OpenAPI; agents and
aggregators may consume any directory or several. The schema lives in
`spec/schemas/listing.json` and is versioned alongside the spec.

Recommended federation patterns:

- **Mirrors**: clone `dump.json.gz` daily; serve identical content
  under their own domain. The daily snapshot URLs let mirrors prove
  they hold the canonical data.
- **Aggregators**: combine the canonical directory with their own
  curation, scan results, or editorial annotations under
  `_meta["<their-domain>/..."]`.
- **Private directories**: enterprises with internal-only AFAuth
  services run their own directory, never publishing to
  `afauth.org`. The same schema and signed-submission protocol apply.

### D.9 Operator and governance

The canonical directory is operated under a **phased handoff** model
designed to avoid the open-ended single-operator dependency that has
been the most cited governance risk for analogous registries (see
References).

#### D.9.1 Phase 0 — initial launch

AFAuthHQ operates `afauth.org/registry` directly. A public operator
commitment at `https://afauth.org/registry/operator` documents:

- Who has operational authority.
- The actions the operator MAY take unilaterally (routine moderation
  per D.10, infrastructure changes, schema-conformant data
  migrations).
- The actions the operator MUST NOT take unilaterally (delisting a
  service outside the published moderation policy, breaking-change
  schema amendments, censoring listings on ideological grounds).

#### D.9.2 Phase 1 — Directory Steering Committee

Phase 1 is triggered when **either** of the following becomes true,
whichever occurs first:

- **Adoption threshold:** ≥50 listed services controlled by ≥10
  distinct organisations.
- **Time threshold:** 12 months have elapsed since Phase 0 launch.

At the trigger, a Directory Steering Committee is seated:

- At least three maintainers from organisations unaffiliated with
  AFAuthHQ.
- AFAuthHQ retains at most one committee seat.
- The committee adopts the OpenAPI surface and `listing.json` schema
  as the change-controlled contract; subsequent schema or API changes
  require committee approval.
- The committee assumes responsibility for the moderation policy
  (D.10) and the operator commitment (D.9.1).

#### D.9.3 Phase 2 — neutral home

When the directory reaches roughly 200 listed services or 24 months
post-launch, the Steering Committee evaluates donation of the
directory to a neutral standards organisation (e.g., OpenWallet
Foundation, Linux Foundation Networking, or an IETF working-group
home if AFAuth itself standardises there). This phase is contingent
on adoption; this AFAP does not commit to a specific destination.

#### D.9.4 Independent mirrors from day one

The structural lever that reduces the importance of the canonical
operator is **mirror diversity.** AFAuthHQ commits to encouraging at
least one independent mirror of the directory at Phase 0 launch and
to maintaining schema parity such that downstream mirrors can serve
the canonical dataset without modification. If the canonical directory
becomes unreachable or makes a contested moderation decision, a mirror
is the answer — not a fork of the protocol.

### D.10 Take-down policy

The canonical directory's take-down policy (illegal content, malware,
spam, fraudulent claims) is published at
`https://afauth.org/registry/policy`. Operational decisions made by
the canonical directory do not bind mirrors or aggregators, which set
their own policies.

A service controller may withdraw a listing at any time by signing a
`DELETE` request (D.4). Removals propagate via `dump.json.gz` and
`updated_since`.

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

**Listing as a tracking vector.** The directory's bulk-dump endpoint
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

**Privacy of `discovery_doc` snapshots.** The directory caches a copy
of each service's discovery document. Services that wish to rotate
endpoint URLs or attestor lists SHOULD assume cached snapshots remain
visible in the directory's history for the snapshot retention period.

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
  literal copy for three reasons: (1) AFAuth has DIDs, so reverse-DNS
  namespacing is redundant; (2) MCP has no bulk-dump endpoint and
  pagination has become an operational pain point; (3) MCP's
  namespace-auth-only model is weaker than AFAuth's signed-submission
  model. This AFAP keeps MCP's good ideas (soft-delete, `_meta`
  federation, OpenAPI as the federation contract, `updated_since`
  delta) and corrects the known weak points.

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
  directory needs. Commercial aggregators on top of the public dump
  are welcome.

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
