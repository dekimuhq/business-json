import type { z } from "zod";
import {
  bindingRecordSchema, businessJsonSchema, verifierMetadataSchema,
  type BindingRecord, type BusinessJson, type VerifierMetadata,
} from "./schema.js";

export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

function parseWith<T>(schema: z.ZodType<T>, input: unknown): ParseResult<T> {
  const r = schema.safeParse(input);
  if (r.success) return { ok: true, value: r.data };
  const error = r.error.issues
    .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
    .join("; ");
  return { ok: false, error };
}

export function parseBusinessJson(input: unknown): ParseResult<BusinessJson> {
  return parseWith(businessJsonSchema, input);
}

export function parseBindingRecord(input: unknown): ParseResult<BindingRecord> {
  return parseWith(bindingRecordSchema, input);
}

export function parseVerifierMetadata(input: unknown): ParseResult<VerifierMetadata> {
  return parseWith(verifierMetadataSchema, input);
}
