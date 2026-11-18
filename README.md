# business-json

A verifiable answer to "is this site really business X?"

A business publishes its identity at `/.well-known/business.json`. A verifier signs a **binding record** that ties it to the domain. The binding needs two proofs:

- the VAT holder's signature with an EU qualified certificate (QSeal, or a legal representative's QES)
- a DNS record at `_business-json.<domain>`

The file alone proves nothing. A lookalike domain can't borrow a binding, and a domain with no file is *unknown*, not suspicious.

Normative format: [SPEC.md](./SPEC.md) (CC0). JSON Schemas: [`business.schema.json`](business.schema.json), [`binding-record.schema.json`](binding-record.schema.json), [`business-verifier.schema.json`](business-verifier.schema.json).

## CLI

```sh
npx @dekimuhq/business-json validate acme.example
npx @dekimuhq/business-json validate acme.example --verifier https://verify.example
npx @dekimuhq/business-json validate ./business.json   # schema only
```

Exit codes:

- `0` bound
- `1` not bound or invalid
- `2` usage
- `3` no business.json (unknown)

You choose which verifiers you trust. The default is `https://verify.dekimu.com`.

## Library

```ts
import { validateDomain, parseBusinessJson, profileDigest, dnsRecordValue } from "@dekimuhq/business-json";

const r = await validateDomain("acme.example", { trusted: [{ origin: "https://verify.dekimu.com" }] });
if (r.status === "bound") console.log(r.doc.legalName, r.record.authority.organizationIdentifier);
```

Pass `fetchImpl`, `resolveTxt`, `resolveCname` and `now` to test without a network. Pin verifier keys with `trusted: [{ origin, keys: [...] }]`.

Node ≥ 20. Runtime dependency: `zod` 4.

## What a result means

A **bound** result means: the holder of VAT number X controls this domain, according to verifier V. It does not mean the business is honest, solvent or safe to pay. Don't present it as "safe", "scam-proof" or "guaranteed".

## License

Code Apache-2.0 ([LICENSE](LICENSE)). Specification CC0 1.0 ([LICENSE-SPEC](LICENSE-SPEC)).
