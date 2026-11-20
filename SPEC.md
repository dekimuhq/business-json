# business.json — v0.1

**Status:** v0.1 (draft, normative)
**License:** CC0 1.0 (this document) · Apache-2.0 (reference implementation)
**Repository:** https://github.com/dekimuhq/business-json

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174.

---

## Abstract

People, marketplaces and AI assistants keep asking the same question: is this site really the business it claims to be? `business.json` gives a machine-readable answer. A business publishes its identity at `/.well-known/business.json`. A **verifier** checks two things and signs a **binding record** that ties that identity to the domain:

1. The holder of the business's VAT number signed a challenge with an EU qualified certificate, and the certificate names the business.
2. The domain carries a DNS record naming the same VAT number.

The file alone proves nothing. Anyone can write one, including for a lookalike domain. The trust comes from the binding record, and only from verifiers the relying party chose itself.

## Non-goals

- **Not a fraud guarantee.** A bound domain shows that the VAT holder controls that domain. It does not show that the business is honest, solvent or safe to pay.
- **Not a payment check.** v0.1 carries no payment account. Euro-area banks already check payee names (Verification of Payee, Regulation (EU) 2024/886).
- **Not a negative signal.** A domain with no `business.json` is **unknown**. Most legitimate businesses publish none.

---

## 1. The document

A business publishes `https://<domain>/.well-known/business.json` for each domain it lists.
- It is served with `Content-Type: application/json`, without redirects, at no more than 64 KiB after decoding.
- It is UTF-8 I-JSON (RFC 7493), with no duplicate member names and no lone surrogates.
- It conforms to [`business.schema.json`](business.schema.json). A conforming parser MUST reject unknown top-level keys.

| Field | Required | Description |
|---|---|---|
| `businessJsonVersion` | Yes | `"0.1"`. |
| `legalName` | Yes | Registered legal name. It MUST match the qualified certificate's `organizationName` under §3 rule 5. This is how a verifier stops a real company from publishing someone else's name. |
| `tradingName` | No | Self-declared. Consumers MUST NOT display it as part of a bound result (§5, rule 2). |
| `vat` | Yes | VAT number in VIES form: member-state prefix (`EL` for Greece, `XI` for Northern Ireland) followed by the number, upper-case, without separators. Example: `ESB12345678`. |
| `address` | Yes | `street`, `locality` and `country` (ISO 3166-1 alpha-2) are required. `postalCode` and `region` are optional. |
| `domains` | Yes | 1–20 hostnames, lower-case ASCII. Internationalised names MUST be written as A-labels (`xn--…`). No repeats. |
| `contact` | Yes | `email` (required), `phone` (E.164, optional), `url` (HTTPS, optional). |
| `policies` | No | HTTPS URLs: `privacy`, `terms`, `legalNotice`. |
| `binding` | Yes | HTTPS URL of this business's binding record at a verifier (§4). It is a **locator only** (§5, rule 1). |

**Text fields** (names, address parts) MUST NOT contain control characters (Unicode category Cc) or bidirectional override characters (U+202A–U+202E, U+2066–U+2069). **URLs** MUST start with `https://`, use printable ASCII only, and contain no whitespace, so the parsed value is byte-for-byte what was served.

**Rules the JSON Schemas cannot express.** Validators MUST also enforce these:
- No duplicate member names, and no lone surrogates.
- Every base64url value is canonical (§4).
- The binding record's time relations (§4).

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

- **Grammar.** Fields are separated by `;`. Each field is `key=value`, keys are lower-case, and whitespace around fields is ignored. A record whose `v` field is `bj1` is a **bj1 record**. A bj1 record MUST carry `vat` exactly once and no key more than once; otherwise it is malformed. Character-strings in one TXT record are concatenated before parsing.
- **No CNAME.** The record MUST sit at that name. A validator MUST reject the proof if `_business-json.<domain>` is a CNAME. A CNAME there could point at a name someone else controls, for example a dangling SaaS target. A CNAME lookup that fails for any reason other than "no such record" (for example SERVFAIL or a timeout) MUST fail the proof, not skip the rule.
- **Exactly one.** Exactly one bj1 record MUST exist at the name, malformed ones included, and its `vat` MUST equal the document's `vat`.
- **Which domain.** A validator checks the proof for the domain it was asked about. A verifier checks every domain it binds.
- Verifiers SHOULD resolve from more than one network vantage point, and SHOULD validate DNSSEC where the zone is signed.

## 3. Authority: proving control of the VAT number

A VIES lookup shows that a VAT number exists. It does not show who is asking. A verifier MUST therefore prove control before it issues a binding:

1. **Challenge.** The verifier issues a challenge: a JSON object, canonicalised with RFC 8785 (JCS), with these fields:
   - `verifier`: the verifier origin
   - `vat`
   - `domains`: the domain list
   - `profileDigest`: see §4
   - `nonce`: at least 128 random bits
   - `expiresAt`: no more than 24 hours ahead

   Because the challenge names the verifier, a signature one verifier collected cannot be replayed to another.
2. **Signature.** The business signs the challenge with an eIDAS **qualified** certificate. The certificate subject's `organizationIdentifier` (OID 2.5.4.97, ETSI EN 319 412-1 §5.1.4) MUST name the VAT number: `VAT` + country code + `-` + number.
   - For Greece, a verifier MUST accept both `VATEL-` and `VATGR-`.
   - For Northern Ireland, it MUST accept both `VATXI-` and `VATGB-`.
   - Matching ignores case and surrounding whitespace.
   - `NTR`, `PSD` and other identifier types do not name a VAT number and MUST NOT be accepted in v0.1.
3. **Certificate kind.** The verifier MUST accept only these:
   - `qseal`: a qualified certificate for electronic seals issued to the legal person (QcType `id-etsi-qct-eseal`).
   - `qes-representative`: a qualified certificate for electronic signatures whose certificate policy is on the verifier's published allowlist of policies that denote **legal representation of the organisation**. One example is Spain's FNMT AC Representación profiles.

   An employee or professional certificate that merely carries the employer's identifier MUST NOT be accepted. The verifier records the matched policy OIDs in `authority.certificatePolicies`.
4. **Chain and status.** The certificate MUST chain to a qualified trust service listed on an EU member-state Trusted List at signing time. The verifier MUST check its revocation status at signing time, by OCSP or CRL, and record the time in `authority.revocationCheckedAt`. It MUST re-check revocation at least every 24 hours while the binding is served, and MUST withdraw the binding (§6) on revocation.
5. **Name.** The verifier MUST record the certificate subject's `organizationName` (OID 2.5.4.10) as `authority.organizationName`. It MUST refuse to bind unless the document's `legalName` matches that name under this comparison: Unicode NFKD, remove combining marks, upper-case, then drop everything that is not a letter or a digit. So `Acme Ejemplo, S.L.` matches `ACME EJEMPLO SL`, but `Amazon EU S.à r.l.` never matches a certificate issued to someone else.

VIES MAY be queried as corroboration and stored as `vies` (only when VIES answers "valid"; omit it otherwise). It MUST NOT be a gate. Many domestic-only businesses are not in VIES, and the qualified certificate already proves the identifier.

**There is no self-declared level.** A binding on VIES + DNS alone would answer a lookup with the real company's registry name for whoever claimed its VAT number first. That vouches for the impersonator. v0.1 therefore defines only `authority`.

## 4. The binding record

The verifier serves the record at the document's `binding` URL. It conforms to [`binding-record.schema.json`](binding-record.schema.json):

| Field | Description |
|---|---|
| `bindingRecordVersion` | `"0.1"`. |
| `verifier` | The verifier origin (`https://host[:port]`, nothing after it). MUST equal the origin serving the record. |
| `vat` | As in the document. |
| `level` | `"authority"`. |
| `authority` | `method`, `organizationIdentifier`, `organizationName`, `certificatePolicies`, `certificateSha256`, `certificateNotAfter`, `signedAt`, `revocationCheckedAt`, and `trustedListSequence` (optional). |
| `vies` | Optional snapshot: `valid` (always `true`), `name`, `address`, `checkedAt`, `requestIdentifier`. |
| `domains` | `{ domain, dnsCheckedAt, registeredAt? }` for each domain bound. `registeredAt` is the RDAP registration date, where the registry offers RDAP. |
| `profileDigest` | `sha256:<hex>` of the JCS form of the `business.json` **as served** (the parsed JSON value, not a normalised copy). If the document changes, it no longer validates until the verifier re-binds it. This stops an attacker who gains write access to the site from swapping the contact details. |
| `issuedAt`, `expiresAt` | `issuedAt < expiresAt ≤ authority.certificateNotAfter`, and `expiresAt − issuedAt` MUST NOT exceed **30 days**. The short lifetime bounds the damage of a leaked or retired key: a key's window bounds `issuedAt`, so a backdated record still expires within 30 days of the key's `notAfter`. It also bounds a lapsed domain (§8). Verifiers renew records after re-checking DNS, revocation and RDAP. |
| `sig` | `{ alg: "ed25519", kid, value }`. `value` is the base64url ed25519 signature over the JCS form of the record without `sig`. |

All times are RFC 3339 UTC with a `Z` suffix. Every base64url value MUST be the canonical encoding of its bytes: no padding, and spare bits zero.

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

- `kid`s are unique and use only `[A-Za-z0-9._:-]`.
- A key's `notBefore` and `notAfter` bound the `issuedAt` of the records it may sign.
- A verifier SHOULD append each binding it issues and withdraws to an append-only transparency log, so a forged or silently removed binding can be detected.

## 5. Trust

1. **Relying parties choose their verifiers out of band.** A validator MUST NOT trust a verifier just because a document names it: anyone can run a verifier and sign their own records. The `binding` URL only locates the record. Validators SHOULD pin keys per verifier. Keys fetched from the verifier's own web host make a hosting compromise equivalent to a signing-key compromise. A tool that ships a default verifier MUST ship that verifier's keys pinned.
2. **Display.** Show only attested values from a bound result:
   - the VAT number
   - `authority.organizationName`
   - the domain
   - the verifier

   Never show the document's `legalName` or `tradingName` as part of the result. A consumer, including an AI assistant summarising a result, MUST phrase it as "the holder of VAT number X (organisation name Y) controls this domain, per verifier V". It MUST NOT present it as "safe", "scam-proof" or "guaranteed". It MUST present an unbound or missing result as "not verified", never as "fraudulent". Untrusted strings, such as reasons, MUST be escaped before display.
3. **Lookalikes.** A lookalike domain cannot borrow a binding. Its DNS proof would need the VAT holder's qualified signature over a challenge that lists that exact domain. Lookalike detection itself is out of scope for this specification.

## 6. Validation

To validate a domain against a set of trusted verifiers, a validator MUST:

1. **Normalise the input before any network or DNS request.** Trim it, strip one trailing dot, convert IDNs to A-labels and lower-case. Refuse anything that is not a hostname under §1: IP literals, ports, paths, user-info.
2. **Fetch** `https://<domain>/.well-known/business.json` without following redirects. Give up after 10 seconds. Refuse a `Content-Type` other than `application/json`, and refuse more than 64 KiB, counted after content decoding while the body streams, never after buffering it whole.
   - HTTP 404 or 410 means **no-profile** (unknown).
   - Any other failure means **not-bound**.
3. **Parse the document strictly** (§1). The domain MUST appear in `domains`.
4. **Check the DNS proof** for the domain (§2).
5. **Find the verifier.** The origin of `binding` MUST be a trusted verifier. Fetch the record under the same rules as step 2. A 404 or 410 means the verifier **withdrew** the binding: the result is not-bound. A validator MUST NOT use a cached or document-supplied record in place of a fresh fetch.
6. **Parse the record strictly** (§4) and check all of the following:
   - `verifier` equals that origin.
   - Exactly one known key has the record's `kid` (pinned, or from the verifier's metadata, whose `verifier` MUST equal the origin). That key is valid at `issuedAt`.
   - The signature verifies.
   - `vat` equals the document's `vat`.
   - `authority.organizationIdentifier` names that VAT (§3, rule 2).
   - The document's `legalName` matches `authority.organizationName` (§3, rule 5).
   - The domain appears in the record's `domains`.
   - `issuedAt − 5 min ≤ now < expiresAt`. A record may be issued up to 5 minutes in the future, to allow for clock skew.
   - `expiresAt − issuedAt ≤ 30 days`.
   - `profileDigest` equals the digest of the document as fetched.
7. **Result.** The result is **bound** only if every check passes. Otherwise it is **not-bound**.

**Withdrawal.** A verifier withdraws a binding by no longer serving its record (HTTP 404 or 410). It MUST withdraw it when:
- the certificate is revoked
- the DNS proof disappears
- the RDAP registration date of a bound domain changes, which means the domain changed hands
- the business asks

A verifier MUST re-check DNS, and RDAP where available, at least every 24 hours while a binding is served.

## 7. Privacy

v0.1 binds legal persons only, since the `authority` methods require an organisation identifier. Natural persons (sole traders) are out of scope until a profile exists that does not publish a home address. Verifiers SHOULD rate-limit lookups by VAT number.

## 8. Security considerations

- **Verifier key compromise** lets an attacker forge bindings. Mitigations:
  - key pinning (§5)
  - the 30-day record cap, which also bounds a backdated record from a retired key (§4)
  - the transparency log (§4)
- **Verifier web-host compromise** is equivalent to key compromise for validators that fetch keys instead of pinning them (§5, rule 1).
- **Site compromise** cannot change a bound document without breaking `profileDigest`. It can remove the document, which turns the result into no-profile: unknown, not a positive signal.
- **DNS compromise** of the business's zone defeats the domain proof for that zone, as it does for every DNS-based proof. It does not give the attacker a qualified signature.
- **Lapsed domains.** The TXT value is public. Someone who registers a domain the business let lapse can copy both the document and the TXT record. The result stays bound until the verifier's RDAP re-check withdraws the binding (at most 24 hours where RDAP exists) or the record expires (at most 30 days). For registries without RDAP, the 30-day cap is the bound.
- **Former representatives.** A binding lives no longer than the certificate behind it, and revocation is re-checked daily.
- **Server-side validators** take attacker-chosen domains. Besides step 1, they MUST block private and link-local address ranges at the network egress, because a valid hostname can still resolve to one.

## Related work

GLEIF's verifiable LEI (vLEI, ISO 17442-3) is a related but different approach: it binds a legal entity, identified by its LEI, to people and roles through a credential chain rooted at GLEIF, and its credentials do not themselves bind a domain or a VAT number; this specification does not depend on it and claims no equivalence to it.

## Reference implementation

```
npx @dekimuhq/business-json validate <domain> [--verifier https://origin …]
npx @dekimuhq/business-json check-file <business.json>
```

Exit codes:
- `0` bound
- `1` not bound or invalid
- `2` usage
- `3` no business.json (unknown)
- `4` `check-file`: the file passes the schema, which says nothing about binding

With no `--verifier`, the CLI trusts `https://verify.dekimu.com` with **pinned** keys. Until that verifier mints its key, the default binds nothing (fail closed), and the package cannot be published.
