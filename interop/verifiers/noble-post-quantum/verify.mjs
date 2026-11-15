// @noble/post-quantum ML-DSA-87 over a cases file.
// usage: node verify.mjs CASES.tsv NOBLE_DIR
//   NOBLE_DIR is a folder with a package.json beside a node_modules that holds @noble/post-quantum.
// Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const [cases, dir] = process.argv.slice(2);
if (!cases || !dir || process.argv.length !== 4) { console.error("usage: verify.mjs CASES.tsv NOBLE_DIR"); process.exit(2); }
const fail = (m) => { console.error(m); process.exit(2); };
let ml_dsa87, ver;
try {
  const req = createRequire(dir + "/package.json");
  ({ ml_dsa87 } = await import(req.resolve("@noble/post-quantum/ml-dsa.js")));
  ver = JSON.parse(readFileSync(dir + "/node_modules/@noble/post-quantum/package.json", "utf8")).version;
} catch (e) { fail("cannot load @noble/post-quantum from " + dir); }
const b = (s) => { if (s === "-") return new Uint8Array(0); if (!/^(?:[0-9a-fA-F]{2})+$/.test(s)) fail("bad hex"); return Uint8Array.from(Buffer.from(s, "hex")); };
let text;
try { text = readFileSync(cases, "utf8"); } catch (e) { fail("cannot read " + cases); }
let n = 0;
const wrong = [];
for (const row of text.split("\n")) {
  if (!row) continue;
  const f = row.split("\t");
  if (f.length !== 6) fail("bad line");
  const [id, pk, sig, msg, ctx, e] = f;
  if (e !== "0" && e !== "1") fail("bad expected result in case " + id);
  const P = b(pk), S = b(sig), M = b(msg), X = ctx === "-" ? null : b(ctx);
  let got;
  try {
    got = ml_dsa87.verify(S, M, P, X === null ? {} : { context: X }) === true;
  } catch {
    got = false;
  }
  n++;
  if (got !== (e === "1")) wrong.push(id);
}
if (n === 0) fail("no cases");
console.log(`@noble/post-quantum ${ver} (Node ${process.version}): ${n} cases, ${wrong.length} disagree with the expected result [${wrong}]`);
process.exit(wrong.length ? 1 : 0);
