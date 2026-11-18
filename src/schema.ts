import { z } from "zod";

/**
 * VIES member-state prefixes (EL = Greece, XI = Northern Ireland). The number
 * part is upper-case, no spaces or separators — the form VIES checkVat takes.
 */
export const VIES_PREFIXES = [
  "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI", "FR", "HR", "HU",
  "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK", "XI",
] as const;

/** A binding record may be valid for at most this long (SPEC §4). Bounds the damage of a leaked key or a lapsed domain. */
export const MAX_RECORD_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

/** Human-readable text: no control characters, so it cannot rewrite a terminal or smuggle line breaks. */
const text = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[^\p{Cc}\u202a-\u202e\u2066-\u2069]+$/u, "must not contain control or bidi-override characters");

/** base64url of exactly `bytes` bytes, in its one canonical spelling (no spare-bit variants). */
const b64url = (bytes: number) =>
  z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .refine((v) => {
      const buf = Buffer.from(v, "base64url");
      return buf.length === bytes && buf.toString("base64url") === v;
    }, `must be the canonical base64url of ${bytes} bytes`);

export const vatSchema = z
  .string()
  .regex(
    new RegExp(`^(${VIES_PREFIXES.join("|")})[0-9A-Z+*]{2,12}$`),
    "vat must be a VIES prefix + number, upper-case, no separators (e.g. ESB12345678)",
  );

/**
 * A DNS hostname in lower-case ASCII. IDNs MUST be written as A-labels
 * (punycode, `xn--…`) so two documents can never spell one domain two ways.
 * The last label must start with a letter, so IPv4 literals never match.
 */
export const domainSchema = z
  .string()
  .max(253)
  .regex(
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
    "domain must be a lower-case ASCII hostname (IDNs as xn-- A-labels)",
  );

export const addressSchema = z.strictObject({
  street: text(300),
  postalCode: text(20).optional(),
  locality: text(200),
  region: text(200).optional(),
  country: z.string().regex(/^[A-Z]{2}$/, "country must be ISO 3166-1 alpha-2"),
});

/**
 * An https URL kept byte-for-byte as written. zod's z.url() trims and strips
 * tab/CR/LF in its output, which would make a digest over the parsed value differ
 * from one over the served bytes; printable ASCII only, so nothing to strip.
 */
const httpsUrl = z
  .string()
  .max(2048)
  .regex(/^https:\/\/[\x21-\x7e]+$/, "must be an https URL (printable ASCII, no whitespace)")
  .refine((v) => URL.canParse(v), "must be a valid URL");

/** An https origin with nothing after it: `https://host[:port]`. */
const httpsOrigin = httpsUrl.refine((v) => URL.canParse(v) && new URL(v).origin === v, "must be a bare https origin, e.g. https://verify.example");

export const contactSchema = z.strictObject({
  email: z.email(),
  phone: z.string().regex(/^\+[1-9][0-9]{6,14}$/, "phone must be E.164, e.g. +34600000000").optional(),
  url: httpsUrl.optional(),
});

export const policiesSchema = z.strictObject({
  privacy: httpsUrl.optional(),
  terms: httpsUrl.optional(),
  legalNotice: httpsUrl.optional(),
});

/** The document a business publishes at `https://<domain>/.well-known/business.json`. */
export const businessJsonSchema = z
  .strictObject({
    businessJsonVersion: z.literal("0.1"),
    /** MUST match the qualified certificate's organizationName (SPEC §3, rule 5). */
    legalName: text(300),
    /** Self-declared. Never displayed as part of a bound result (SPEC §5, rule 2). */
    tradingName: text(300).optional(),
    vat: vatSchema,
    address: addressSchema,
    domains: z.array(domainSchema).min(1).max(20),
    contact: contactSchema,
    policies: policiesSchema.optional(),
    /** HTTPS URL of this business's binding record at a verifier. A locator only. */
    binding: httpsUrl,
  })
  .refine((d) => new Set(d.domains).size === d.domains.length, {
    message: "domains must not repeat",
    path: ["domains"],
  });

export const viesSnapshotSchema = z.strictObject({
  valid: z.literal(true),
  name: text(500).optional(),
  address: text(1000).optional(),
  checkedAt: z.iso.datetime(),
  requestIdentifier: text(200).optional(),
});

const oid = z.string().regex(/^[0-2](\.(0|[1-9][0-9]*))+$/, "must be a dotted OID");

/** SPEC §3: how the verifier proved the VAT holder signed the challenge. */
export const authorityEvidenceSchema = z.strictObject({
  method: z.enum(["qseal", "qes-representative"]),
  /** Subject organizationIdentifier (OID 2.5.4.97) of the qualified certificate, e.g. `VATES-B12345678`. */
  organizationIdentifier: text(100),
  /** Subject organizationName (OID 2.5.4.10) of the qualified certificate — the only name a bound result shows. */
  organizationName: text(300),
  /** Certificate policy OIDs the verifier matched against its allowlist (SPEC §3, rule 3). */
  certificatePolicies: z.array(oid).min(1),
  certificateSha256: z.string().regex(/^[0-9a-f]{64}$/),
  certificateNotAfter: z.iso.datetime(),
  signedAt: z.iso.datetime(),
  revocationCheckedAt: z.iso.datetime(),
  trustedListSequence: text(100).optional(),
});

export const bindingDomainSchema = z.strictObject({
  domain: domainSchema,
  dnsCheckedAt: z.iso.datetime(),
  /** RDAP registration date when the registry offers RDAP (SPEC §6, withdrawal on change of hands). */
  registeredAt: z.iso.datetime().optional(),
});

const kid = z.string().min(1).max(200).regex(/^[A-Za-z0-9._:-]+$/, "kid must be [A-Za-z0-9._:-]");

export const signatureSchema = z.strictObject({
  alg: z.literal("ed25519"),
  kid,
  /** base64url ed25519 signature over the JCS form of the record without `sig`. */
  value: b64url(64),
});

/** The record a verifier signs and serves at the document's `binding` URL. */
export const bindingRecordSchema = z
  .strictObject({
    bindingRecordVersion: z.literal("0.1"),
    verifier: httpsOrigin,
    vat: vatSchema,
    /**
     * v0.1 has one level. A self-declared level (VAT valid in VIES, control not
     * proven) was rejected in review: it echoes the real company's registry name
     * back to whoever claimed its VAT first, which vouches for the impersonator.
     */
    level: z.literal("authority"),
    authority: authorityEvidenceSchema,
    /** Optional corroboration. Not a gate: many domestic-only businesses are not in VIES. */
    vies: viesSnapshotSchema.optional(),
    domains: z.array(bindingDomainSchema).min(1).max(20),
    /** `sha256:<hex>` of the JCS form of the business.json the verifier saw. */
    profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    issuedAt: z.iso.datetime(),
    expiresAt: z.iso.datetime(),
    sig: signatureSchema,
  })
  .refine((r) => Date.parse(r.expiresAt) <= Date.parse(r.authority.certificateNotAfter), {
    message: "expiresAt must not be later than the certificate's notAfter",
    path: ["expiresAt"],
  })
  .refine((r) => Date.parse(r.expiresAt) > Date.parse(r.issuedAt), {
    message: "expiresAt must be after issuedAt",
    path: ["expiresAt"],
  })
  .refine((r) => Date.parse(r.expiresAt) - Date.parse(r.issuedAt) <= MAX_RECORD_LIFETIME_MS, {
    message: "a binding record may be valid for at most 30 days",
    path: ["expiresAt"],
  });

export const verifierKeySchema = z.strictObject({
  kid,
  alg: z.literal("ed25519"),
  /** base64url raw 32-byte public key (JWK `x`). */
  x: b64url(32),
  notBefore: z.iso.datetime().optional(),
  notAfter: z.iso.datetime().optional(),
});

/** Served at `https://<verifier>/.well-known/business-verifier.json`. */
export const verifierMetadataSchema = z.strictObject({
  businessVerifierVersion: z.literal("0.1"),
  verifier: httpsOrigin,
  keys: z.array(verifierKeySchema).min(1),
  lookup: httpsUrl.optional(),
});

export type BusinessJson = z.infer<typeof businessJsonSchema>;
export type BindingRecord = z.infer<typeof bindingRecordSchema>;
export type VerifierMetadata = z.infer<typeof verifierMetadataSchema>;
export type VerifierKey = z.infer<typeof verifierKeySchema>;
