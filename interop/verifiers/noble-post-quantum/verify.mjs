// @noble/post-quantum ML-DSA-87 over a cases file.
// usage: node verify.mjs CASES.tsv NOBLE_DIR
//   NOBLE_DIR is a folder with a package.json beside a node_modules that holds @noble/post-quantum.
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const [cases, dir] = process.argv.slice(2);
if (!cases || !dir) process.exit(2);
const req = createRequire(dir + "/package.json");
const { ml_dsa87 } = await import(req.resolve("@noble/post-quantum/ml-dsa.js"));
const ver = JSON.parse(readFileSync(dir + "/node_modules/@noble/post-quantum/package.json", "utf8")).version;
const b = (s) => (s === "-" ? new Uint8Array(0) : Uint8Array.from(Buffer.from(s, "hex")));
let n = 0;
const wrong = [];
for (const row of readFileSync(cases, "utf8").split("\n")) {
  if (!row) continue;
  const f = row.split("\t");
  if (f.length !== 6) process.exit(2);
  const [id, pk, sig, msg, ctx, e] = f;
  let got;
  try {
    got = ml_dsa87.verify(b(sig), b(msg), b(pk), ctx === "-" ? {} : { context: b(ctx) }) === true;
  } catch {
    got = false;
  }
  n++;
  if (got !== (e === "1")) wrong.push(id);
}
console.log(`@noble/post-quantum ${ver} (Node ${process.version}): ${n} cases, ${wrong.length} disagree with the expected result [${wrong}]`);
process.exit(wrong.length ? 1 : 0);
