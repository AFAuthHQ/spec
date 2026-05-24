# AFAP-0004: x402 payment binding

**Status:** Draft
**Author:** Editor
**Filed:** 2026-05-24
**Affects:** `spec/schemas/well-known.json` (adds optional `x402` block). No normative changes to `spec/core.md`.

## Summary

Define a minimum opt-in binding between AFAuth and Coinbase's x402 payment protocol so an x402 payment can be attributed to an AFAuth account. Two pieces: (1) services advertise x402 acceptance in the existing `/.well-known/afauth` document; (2) clients tag the x402 request with their AFAuth account identifier under an ordinary AFAuth request signature.

## Motivation

x402 is stateless by design and has no native answer for subscriptions, spend caps, refunds, receipts, or "is this the same agent as yesterday." AFAuth supplies those natively. The minimum binding lets services tag every x402 payment with the AFAuth account that authorised it, with no new cryptography and no new identity layer.

## Specification

### X.1 Discovery

A service that accepts x402 MAY include an `x402` block in `/.well-known/afauth`:

```json
"x402": {
  "facilitator":      "https://x402.org/facilitator",
  "networks":         ["eip155:8453", "solana:mainnet"],
  "assets":           ["eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"],
  "payment_endpoint": "https://api.example.com/pay"
}
```

All four fields are REQUIRED when the block is present. `networks` carries CAIP-2 identifiers; `assets` carries CAIP-19 identifiers. Absence of the block makes no statement about x402 support.

### X.2 Account attribution

A client paying via x402 against a service that also issues it an AFAuth account SHOULD include the `X-AFAuth-Account` header on the request:

```http
X-AFAuth-Account: <account_id>
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "x-afauth-account");
                 created=…;keyid="<agent_did>";alg="ed25519"
Signature: sig1=:…:
```

The signature is an ordinary AFAuth request signature per `core.md` §5 and MUST cover `x-afauth-account`. The service MUST verify the signature against the account's bound key set before crediting the payment to the account. Receipts, subscription rollups, and service-defined spend caps then apply to the account, not to the payer wallet.

A payment without `X-AFAuth-Account`, or with an unverifiable signature, is processed as a vanilla x402 payment with no account attribution; the service MUST NOT refuse settlement on that ground alone.

### X.3 Key independence

The x402 payer wallet and the AFAuth signing key are independent. EVM payments necessarily use secp256k1, which is not in AFAuth's algorithm set (§5); same-key reuse is practical only for Solana (ed25519). This AFAP defines no derivation scheme.

## Compatibility

Wire-compatible. The `x402` block is additive and optional. The `X-AFAuth-Account` header is ignored by x402-only clients and not encountered by AFAuth-only services. A service may adopt either protocol without the other.

## Security and privacy considerations

- **Account-binding forgery.** An attacker who could attribute a payment to another account would reach that account's receipts and spend caps. The §X.2 signature requirement forecloses this: forgery requires the account's private key.
- **`account_id` linkability.** The header reveals to the facilitator and any intermediary that this payment is tied to a particular AFAuth account. Clients that want unlinkable payments omit the header and lose attribution.
- **No new trust anchor.** No new keys, DIDs, or authorities; the facilitator is whichever facilitator x402 already trusts; the account is whichever account AFAuth already issued.

## References

- `spec/core.md` §5 (HTTP Message Signatures).
- [Coinbase x402](https://github.com/coinbase/x402).
- [CAIP-2](https://chainagnostic.org/CAIPs/caip-2), [CAIP-19](https://chainagnostic.org/CAIPs/caip-19).
