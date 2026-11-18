/**
 * ETSI EN 319 412-1 §5.1.4 writes a VAT-based organizationIdentifier as
 * `VAT` + ISO 3166-1 country code + `-` + number. VIES uses `EL` for Greece and
 * `XI` for Northern Ireland; a 319 412-1 NOTE allows `EL`, and some QTSPs write
 * the ISO code instead. Both spellings are accepted for those two.
 */
const ALIASES: Readonly<Record<string, readonly string[]>> = {
  EL: ["EL", "GR"],
  XI: ["XI", "GB"],
};

/** Every organizationIdentifier spelling that names the same VIES-form VAT. */
export function organizationIdentifiersFor(vat: string): string[] {
  const prefix = vat.slice(0, 2);
  const number = vat.slice(2);
  return (ALIASES[prefix] ?? [prefix]).map((cc) => `VAT${cc}-${number}`);
}

/** True when a certificate's organizationIdentifier names this VAT. */
export function organizationIdentifierMatches(vat: string, organizationIdentifier: string): boolean {
  return organizationIdentifiersFor(vat).includes(organizationIdentifier.trim().toUpperCase());
}
