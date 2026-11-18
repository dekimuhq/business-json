import { z } from "zod";

/**
 * VIES member-state prefixes (EL = Greece, XI = Northern Ireland). The number
 * part is upper-case, no spaces or separators — the form VIES checkVat takes.
 */
export const VIES_PREFIXES = [
  "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI", "FR", "HR", "HU",
  "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK", "XI",
] as const;

export const vatSchema = z
  .string()
  .regex(
    new RegExp(`^(${VIES_PREFIXES.join("|")})[0-9A-Z+*]{2,12}$`),
    "vat must be a VIES prefix + number, upper-case, no separators (e.g. ESB12345678)",
  );

/**
 * A DNS hostname in lower-case ASCII. IDNs MUST be written as A-labels
 * (punycode, `xn--…`) so two documents can never spell one domain two ways.
 */
export const domainSchema = z
  .string()
  .max(253)
  .regex(
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
    "domain must be a lower-case ASCII hostname (IDNs as xn-- A-labels)",
  );

export const addressSchema = z.strictObject({
  street: z.string().min(1).max(300),
  postalCode: z.string().min(1).max(20).optional(),
  locality: z.string().min(1).max(200),
  region: z.string().min(1).max(200).optional(),
  country: z.string().regex(/^[A-Z]{2}$/, "country must be ISO 3166-1 alpha-2"),
});

export const contactSchema = z.strictObject({
  email: z.email(),
  phone: z.string().regex(/^\+[1-9][0-9]{6,14}$/, "phone must be E.164, e.g. +34600000000").optional(),
  url: z.url({ protocol: /^https$/ }).optional(),
});

const httpsUrl = z.url({ protocol: /^https$/ });

export const policiesSchema = z.strictObject({
  privacy: httpsUrl.optional(),
  terms: httpsUrl.optional(),
  legalNotice: httpsUrl.optional(),
});

/** The document a business publishes at `https://<domain>/.well-known/business.json`. */
export const businessJsonSchema = z
  .strictObject({
    businessJsonVersion: z.literal("0.1"),
    legalName: z.string().min(1).max(300),
    tradingName: z.string().min(1).max(300).optional(),
    vat: vatSchema,
    address: addressSchema,
    domains: z.array(domainSchema).min(1).max(20),
    contact: contactSchema,
    policies: policiesSchema.optional(),
    /** HTTPS URL of this business's binding record at a verifier. */
    binding: httpsUrl,
  })
  .refine((d) => new Set(d.domains).size === d.domains.length, {
    message: "domains must not repeat",
    path: ["domains"],
  });

export const viesSnapshotSchema = z.strictObject({
  valid: z.literal(true),
  name: z.string().max(500).optional(),
  address: z.string().max(1000).optional(),
  checkedAt: z.iso.datetime(),
  requestIdentifier: z.string().max(200).optional(),
});

const oid = z.string().regex(/^[0-2](\.(0|[1-9][0-9]*))+$/, "must be a dotted OID");

/** SPEC §Authority: how the verifier proved the VAT holder signed the challenge. */
export const authorityEvidenceSchema = z.strictObject({
  method: z.enum(["qseal", "qes-representative"]),
  /** Subject organizationIdentifier (OID 2.5.4.97) of the qualified certificate, e.g. `VATES-B12345678`. */
  organizationIdentifier: z.string().min(3).max(100),
  /** Certificate policy OIDs the verifier matched against its allowlist (SPEC §Authority, rule 3). */
  certificatePolicies: z.array(oid).min(1),
  certificateSha256: z.string().regex(/^[0-9a-f]{64}$/),
  certificateNotAfter: z.iso.datetime(),
  signedAt: z.iso.datetime(),
  revocationCheckedAt: z.iso.datetime(),
  trustedListSequence: z.string().max(100).optional(),
});

export const bindingDomainSchema = z.strictObject({
  domain: domainSchema,
  dnsCheckedAt: z.iso.datetime(),
});

export const signatureSchema = z.strictObject({
  alg: z.literal("ed25519"),
  kid: z.string().min(1).max(200),
  /** base64url ed25519 signature over the JCS form of the record without `sig`. */
  value: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
});

/** The record a verifier signs and serves at the document's `binding` URL. */
export const bindingRecordSchema = z
  .strictObject({
    bindingRecordVersion: z.literal("0.1"),
    verifier: httpsUrl,
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
  });

export const verifierKeySchema = z.strictObject({
  kid: z.string().min(1).max(200),
  alg: z.literal("ed25519"),
  /** base64url raw 32-byte public key (JWK `x`). */
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  notBefore: z.iso.datetime().optional(),
  notAfter: z.iso.datetime().optional(),
});

/** Served at `https://<verifier>/.well-known/business-verifier.json`. */
export const verifierMetadataSchema = z.strictObject({
  businessVerifierVersion: z.literal("0.1"),
  verifier: httpsUrl,
  keys: z.array(verifierKeySchema).min(1),
  lookup: httpsUrl.optional(),
});

export type BusinessJson = z.infer<typeof businessJsonSchema>;
export type BindingRecord = z.infer<typeof bindingRecordSchema>;
export type VerifierMetadata = z.infer<typeof verifierMetadataSchema>;
export type VerifierKey = z.infer<typeof verifierKeySchema>;
