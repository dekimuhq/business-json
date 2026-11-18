# business.json — v0.1

**Status:** v0.1 (draft, normative)
**License:** CC0 1.0 (this document) · Apache-2.0 (reference implementation)
**Repository:** https://github.com/dekimuhq/business-json

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174.

---

## Abstract

People, marketplaces and AI assistants keep asking the same question: is this site really the business it claims to be? `business.json` gives a machine-readable answer. A business publishes its identity at `/.well-known/business.json`. A **verifier** checks two things and signs a **binding record** that ties that identity to the domain:

1. The holder of the business's VAT number signed a challenge with an EU qualified certificate.
2. The domain carries a DNS record naming the same VAT number.

The file alone proves nothing. Anyone can write one, including for a lookalike domain. The trust comes from the binding record, and only from verifiers the relying party chose itself.

## Non-goals

- **Not a fraud guarantee.** A bound domain shows that the VAT holder controls that domain. It does not show that the business is honest, solvent or safe to pay.
- **Not a payment check.** v0.1 carries no payment account. Euro-area banks already check payee names (Verification of Payee, Regulation (EU) 2024/886).
- **Not a negative signal.** A domain with no `business.json` is **unknown**. Most legitimate businesses publish none.

---

## 1. The document

A business publishes `https://<domain>/.well-known/business.json` for each domain it lists. It is served with `Content-Type: application/json`, without redirects, at no more than 64 KiB. It is a JSON object conforming to [`business.schema.json`](business.schema.json). A conforming parser MUST reject unknown top-level keys.

| Field | Required | Description |
|---|---|---|
| `businessJsonVersion` | Yes | `"0.1"`. |
| `legalName` | Yes | Registered legal name. |
| `tradingName` | No | Name used with customers. |
| `vat` | Yes | VAT number in VIES form: member-state prefix (`EL` for Greece, `XI` for Northern Ireland) followed by the number, upper-case, without separators. Example: `ESB12345678`. |
| `address` | Yes | `street`, `locality` and `country` (ISO 3166-1 alpha-2) are required. `postalCode` and `region` are optional. |
| `domains` | Yes | 1–20 hostnames, lower-case ASCII. Internationalised names MUST be written as A-labels (`xn--…`). No repeats. |
| `contact` | Yes | `email` (required), `phone` (E.164, optional), `url` (HTTPS, optional). |
| `policies` | No | HTTPS URLs: `privacy`, `terms`, `legalNotice`. |
| `binding` | Yes | HTTPS URL of this business's binding record at a verifier (§4). It is a **locator only** (§5, rule 1). |

### Example

```json
{
  "businessJsonVersion": "0.1",
  "legalName": "Acme Ejemplo, S.L.",
  "vat": "ESB12345678",
  "address": { "street": "Calle Mayor 1", "postalCode": "28001", "locality": "Madrid", "country": "ES" },
  "domains": ["acme.example"],
  "contact": { "email": "hola@acme.example" },
  "binding": "https://verify.dekimu.com/b/ESB12345678/binding.json"
}
```

## 2. Domain proof

For each domain in `domains`, the business publishes a TXT record at `_business-json.<domain>`:

```
_business-json.acme.example.  TXT  "v=bj1; vat=ESB12345678"
```

- The record MUST sit at that name. A validator MUST reject the proof if `_business-json.<domain>` is a CNAME. A CNAME there could point at a name that someone else controls, for example a dangling SaaS target.
- Exactly one `v=bj1` record MUST exist at the name, and its `vat` MUST equal the document's `vat`.
- Verifiers SHOULD resolve from more than one network vantage point, and SHOULD validate DNSSEC where the zone is signed.

## 3. Authority: proving control of the VAT number

A VIES lookup shows that a VAT number exists. It does not show who is asking. A verifier MUST therefore prove control before it issues a binding:

1. **Challenge.** The verifier issues a challenge. It is a JSON object canonicalised with RFC 8785 (JCS) and contains:
   - `verifier`: the verifier origin
   - `vat`
   - `domains`: the domain list
   - `profileDigest`: §4
   - `nonce`: at least 128 random bits
   - `expiresAt`: no more than 24 hours ahead

   Because the challenge names the verifier, a signature collected by one verifier cannot be replayed to another.
2. **Signature.** The business signs the challenge with an eIDAS **qualified** certificate. The certificate subject's `organizationIdentifier` (OID 2.5.4.97, ETSI EN 319 412-1 §5.1.4) MUST name the VAT number: `VAT` + country code + `-` + number. For Greece, a verifier MUST accept both `VATEL-` and `VATGR-`. For Northern Ireland it MUST accept both `VATXI-` and `VATGB-`. `NTR`, `PSD` and other identifier types do not name a VAT number and MUST NOT be accepted in v0.1.
3. **Certificate kind.** The verifier MUST accept only one of these:
   - `qseal`: a qualified certificate for electronic seals issued to the legal person (QcType `id-etsi-qct-eseal`)
   - `qes-representative`: a qualified certificate for electronic signatures whose certificate policy appears on the verifier's published allowlist of policies that denote **legal representation of the organisation** (for example, Spain's FNMT AC Representación profiles)

   An employee or professional certificate that merely carries the employer's identifier MUST NOT be accepted. The verifier MUST record the matched policy OIDs in `authority.certificatePolicies`.
4. **Chain and status.** The certificate MUST chain to a qualified trust service listed on an EU member-state Trusted List at signing time. Its revocation status MUST be checked at signing time, through OCSP or a CRL, and the time recorded in `authority.revocationCheckedAt`. A verifier SHOULD re-check revocation periodically and MUST withdraw the binding (§6) when the certificate is revoked.

VIES MAY be queried as corroboration and stored as `vies`, but it MUST NOT be a gate. Many businesses that trade only domestically are not in VIES, and the qualified certificate already proves the identifier.

**There is no self-declared level.** A binding based on VIES and DNS alone would answer a lookup with the real company's registry name for whoever claimed its VAT number first. That vouches for the impersonator. v0.1 therefore defines only `authority`.

## 4. The binding record

The verifier serves the record at the document's `binding` URL. It conforms to [`binding-record.schema.json`](binding-record.schema.json):

| Field | Description |
|---|---|
| `bindingRecordVersion` | `"0.1"`. |
| `verifier` | The verifier origin. MUST equal the origin that serves the record. |
| `vat` | As in the document. |
| `level` | `"authority"`. |
| `authority` | `method`, `organizationIdentifier`, `certificatePolicies`, `certificateSha256`, `certificateNotAfter`, `signedAt`, `revocationCheckedAt`, and `trustedListSequence` (optional). |
| `vies` | Optional snapshot: `valid`, `name`, `address`, `checkedAt`, `requestIdentifier`. |
| `domains` | `{ domain, dnsCheckedAt }` for each domain bound. |
| `profileDigest` | `sha256:<hex>` of the JCS form of the `business.json` the verifier bound. If the document changes, it no longer validates until the verifier re-binds it. This stops an attacker who gains write access to the site from swapping the contact details. |
| `issuedAt`, `expiresAt` | `expiresAt` MUST NOT be later than `authority.certificateNotAfter`. Verifiers SHOULD issue records valid for no more than 90 days and renew them after re-checking DNS and revocation. |
| `sig` | `{ alg: "ed25519", kid, value }`. `value` is the base64url ed25519 signature over the JCS form of the record without `sig`. |

### Verifier metadata

A verifier publishes `https://<verifier>/.well-known/business-verifier.json` ([`business-verifier.schema.json`](business-verifier.schema.json)):

```json
{
  "businessVerifierVersion": "0.1",
  "verifier": "https://verify.dekimu.com",
  "keys": [{ "kid": "bj-2026-11", "alg": "ed25519", "x": "<base64url 32-byte key>", "notBefore": "2026-11-01T00:00:00Z" }],
  "lookup": "https://verify.dekimu.com/api/b/lookup"
}
```

A key's `notBefore` and `notAfter` bound the `issuedAt` of the records it may sign. A verifier SHOULD also append each binding it issues and withdraws to an append-only transparency log, so that a forged or silently removed binding can be detected.

## 5. Trust

1. **Relying parties choose their verifiers out of band.** A validator MUST NOT trust a verifier just because a document names it: anyone can run a verifier and sign their own records. The `binding` URL only locates the record. Validators SHOULD allow keys to be pinned per verifier.
2. **Display.** A consumer, including an AI assistant summarising a result, MUST present a bound result as "the holder of VAT number X controls this domain, per verifier V". It MUST NOT present it as "safe", "scam-proof" or "guaranteed". It MUST present an unbound or missing result as "not verified", never as "fraudulent".
3. **Lookalikes.** A lookalike domain cannot borrow a binding. Its DNS proof would need the VAT holder's qualified signature over a challenge that lists that exact domain. Lookalike detection itself is out of scope for this specification.

## 6. Validation

To validate `<domain>` against a set of trusted verifiers, a validator MUST:

1. Lower-case the domain and strip any trailing dot. Fetch `https://<domain>/.well-known/business.json` without following redirects, and refuse more than 64 KiB.
   - HTTP 404 or 410: the result is **no-profile** (unknown).
   - Any other failure: **not-bound**.
2. Parse the document strictly (§1). The domain MUST appear in `domains`.
3. Check the DNS proof (§2).
4. Require the origin of `binding` to be a trusted verifier. Fetch the record without redirects.
5. Parse the record strictly (§4). Check all of the following:
   - `verifier` equals that origin.
   - The key `kid` is known (pinned, or from the verifier's metadata) and valid at `issuedAt`.
   - The signature verifies.
   - `vat` equals the document's `vat`.
   - `authority.organizationIdentifier` names that VAT (§3, rule 2).
   - The domain appears in the record's `domains`.
   - `issuedAt ≤ now < expiresAt`.
   - `profileDigest` equals the digest of the fetched document.
6. The result is **bound** only if every check passes. Otherwise it is **not-bound**.

**Withdrawal.** A verifier withdraws a binding by no longer serving its record (HTTP 404 or 410). It MUST withdraw it when any of these happen:
- the certificate is revoked
- the DNS proof disappears
- the registration date of a bound domain changes in RDAP (the domain changed hands)
- the business asks

## 7. Privacy

v0.1 binds legal persons only. The `authority` methods require an organisation identifier. Natural persons (sole traders) are out of scope until a profile exists that does not publish a home address. Verifiers SHOULD rate-limit lookups by VAT number.

## 8. Security considerations

- **Verifier key compromise** lets an attacker forge bindings. The mitigations are key pinning (§5), short record lifetimes (§4) and the transparency log (§4).
- **Site compromise** cannot change a bound document without breaking `profileDigest`. It can remove the document, which turns the result into no-profile, an unknown rather than a positive signal.
- **DNS compromise** of the business's zone defeats the domain proof for that zone, as it does for every DNS-based proof. It does not give the attacker a qualified signature.
- **Former representatives.** A binding lives no longer than the certificate behind it, and revocation is re-checked.

## Reference implementation

`npx @dekimuhq/business-json validate <domain> [--verifier https://origin …]`

Exit codes:
- `0` bound
- `1` not bound or invalid
- `2` usage
- `3` no business.json (unknown)

With no `--verifier`, the CLI trusts `https://verify.dekimu.com`. A local `*.json` path is checked against the schema only.
