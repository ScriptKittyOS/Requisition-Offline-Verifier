# @noble/post-quantum

- Library: @noble/post-quantum 0.7.1 (JavaScript), `ml_dsa87.verify`. Measured on Node v22.23.2.
- Where to get it: the npm package `@noble/post-quantum`, version 0.7.1, and the three packages it needs
  (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, each 2.4.0), each pinned by version and SHA-512 in
  `package-lock.json` here. Copy `package.json` and `package-lock.json` into an empty folder and install there;
  `npm ci` refuses a package whose SHA-512 differs from the lock file and runs no install script:

  ```
  cp interop/verifiers/noble-post-quantum/package.json interop/verifiers/noble-post-quantum/package-lock.json "$NOBLE_DIR"/
  (cd "$NOBLE_DIR" && npm ci --ignore-scripts)
  ```

  Check the version in the result line.
- `NOBLE_DIR` is that folder: it holds a `package.json` and `node_modules/@noble/post-quantum`.
- Where the hashes came from: the `integrity` values the npm registry gave for these four versions, copied from a
  lock file made from the registry. The registry serves the packages and these values over the same HTTPS connection, so
  they show that the files are the ones the registry listed, not who built them.

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
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.
