// scripts/gen-schema.mjs — writes the three normative JSON Schemas from the zod source.
import { writeFileSync } from "node:fs";
import { z } from "zod";
import { bindingRecordSchema, businessJsonSchema, verifierMetadataSchema } from "../dist/schema.js";

const targets = [
  ["business.schema.json", "BusinessJson", businessJsonSchema],
  ["binding-record.schema.json", "BindingRecord", bindingRecordSchema],
  ["business-verifier.schema.json", "BusinessVerifier", verifierMetadataSchema],
];

for (const [file, name, schema] of targets) {
  const { $schema, ...body } = z.toJSONSchema(schema, { target: "draft-7", io: "input" });
  // The zod refine "domains must not repeat" has no JSON Schema form of its own; uniqueItems is it.
  if (body.properties?.domains?.type === "array" && name === "BusinessJson") body.properties.domains.uniqueItems = true;
  const out = { $ref: `#/definitions/${name}`, definitions: { [name]: body }, $schema };
  writeFileSync(new URL(`../${file}`, import.meta.url), JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${file}`);
}
