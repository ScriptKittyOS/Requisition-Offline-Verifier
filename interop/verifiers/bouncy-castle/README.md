# Bouncy Castle

- Library: Bouncy Castle `bcprov-jdk18on` 1.87 (Java), the lightweight API (`MLDSASigner`). Measured on Java
  21.0.13.0.3.
- Where to get it: Maven Central, `org.bouncycastle:bcprov-jdk18on:1.87`, file `bcprov-jdk18on-1.87.jar`,
  SHA-256 `12d2d3dd82a9ec15e92ec7c7943ee64f6097c6dc12c07e984f1693b77565b9aa`. `BC_JAR` is the path of that file.
- The harness is a single source file that `java` compiles and runs itself (measured with Java 21);
  nothing is written into this repository.

Run, from the top of this repository. The line names the library version that Bouncy Castle itself reports:

```
java -cp "$BC_JAR" interop/verifiers/bouncy-castle/BcVerify.java interop/cases.tsv
```

Result measured 2026-11-14 (Linux x86-64):

```
Bouncy Castle bcprov-jdk18on 1.87 (Java 21.0.13.0.3): 260 cases, 0 disagree with the expected result []
```

## Exit status

0 when no case disagrees with its expected result; 1 when at least one does (the result line names the case ids);
2 when the run is not valid and no result line is printed: a wrong number of arguments, a cases file that cannot be
read, a line that is not six tab-separated fields, a field that is not hex (or `-`), an expected result other than 0 or 1,
or a cases file with no case in it. Only a case that was parsed and given to the library can agree or disagree.
A line of `interop/cases.tsv` has six tab-separated fields: case id, public key, signature, message, context, expected
result (1 or 0), in lower-case hex with `-` for empty.
A line with no characters is skipped; a line of only spaces or tabs is not, and ends the run with exit 2.
