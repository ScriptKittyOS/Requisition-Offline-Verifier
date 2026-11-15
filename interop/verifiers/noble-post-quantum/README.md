# @noble/post-quantum

- Library: @noble/post-quantum 0.7.1 (JavaScript), `ml_dsa87.verify`. Measured on Node v22.23.2.
- Where to get it: the npm package `@noble/post-quantum`, version 0.7.1
  (`npm install @noble/post-quantum@0.7.1` in an empty folder). Check the version in the result line.
- `NOBLE_DIR` is that folder: it holds a `package.json` and `node_modules/@noble/post-quantum`.

Run, from the top of this repository:

```
node interop/verifiers/noble-post-quantum/verify.mjs interop/cases.tsv "$NOBLE_DIR"
```

Result measured 2026-11-14 (Linux x86-64):

```
@noble/post-quantum 0.7.1 (Node v22.23.2): 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
