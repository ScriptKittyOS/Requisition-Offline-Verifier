# Bouncy Castle

- Library: Bouncy Castle `bcprov-jdk18on` 1.87 (Java), the lightweight API (`MLDSASigner`). Measured on Java
  21.0.13.0.3.
- Where to get it: Maven Central, `org.bouncycastle:bcprov-jdk18on:1.87`, file `bcprov-jdk18on-1.87.jar`,
  SHA-256 `12d2d3dd82a9ec15e92ec7c7943ee64f6097c6dc12c07e984f1693b77565b9aa`. `BC_JAR` is the path of that file.
- The harness is a single source file that `java` compiles and runs itself (measured with Java 21);
  nothing is written into this repository.

Run, from the top of this repository. The last argument is the library version, which the line repeats:

```
java -cp "$BC_JAR" interop/verifiers/bouncy-castle/BcVerify.java interop/cases.tsv 1.87
```

Result measured 2026-11-14 (Linux x86-64):

```
Bouncy Castle bcprov-jdk18on 1.87 (Java 21.0.13.0.3): 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 on a bad command line or a malformed cases file. A line of `interop/cases.tsv` has six tab-separated fields: case
id, public key, signature, message, context, expected result (1 or 0), in lower-case hex with `-` for empty.
