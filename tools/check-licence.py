# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Checks this repository's licensing and its pinned downloads. Standard library only; reads files, writes nothing.

  python3 -B -I tools/check-licence.py      exit 0 when every check holds, 1 when one does not (each is printed)

1. LICENSE is the Apache License 2.0 text (its SHA-256), and NOTICE carries the copyright line.
2. Every source file of this repository starts with the SPDX identifier and the copyright line (after a "#!" line,
   where there is one). A source file is a file with one of SOURCE_SUFFIXES, or one that starts with "#!". EXEMPT
   lists the files that do not carry the header, each with its reason, and is exact: an entry that is not a source
   file here, or that already carries the header, is reported too.
3. Every download the interop harnesses use is pinned by an exact version and a hash: each requirement in
   interop/verifiers/pyca-cryptography/requirements.txt is "==" with at least one --hash=sha256, and every package
   of interop/verifiers/noble-post-quantum/package-lock.json has an exact version and a sha512 integrity.
The file list is `git ls-files` in a git checkout, and every file under this folder otherwise (a release archive)."""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPDX = "SPDX-License-Identifier: Apache-2.0"
COPYRIGHT = "Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)"
# The Apache License 2.0 text, byte for byte as the Apache Software Foundation distributes it (11,358 bytes).
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
SOURCE_SUFFIXES = {".py", ".sh", ".c", ".cpp", ".java", ".go", ".mjs", ".escript"}
HEADER_LINES = 5
COMMENT_LEADERS = ("//", "#", "%%", "%")
EXEMPT = {
    "verifier/vendor/mldsa.py": "mldsa-py 1.0.1 by Filippo Valsorda, CC0-1.0 OR 0BSD, byte for byte (verifier/vendor/VENDORED.md)",
}
PYCA_REQUIREMENTS = "interop/verifiers/pyca-cryptography/requirements.txt"
NOBLE_LOCK = "interop/verifiers/noble-post-quantum/package-lock.json"


def files():
    if (ROOT / ".git").exists():
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
        return sorted(name for name in out.decode("utf-8").split("\0") if name)
    found = []
    for folder, _dirs, names in os.walk(ROOT):
        for name in names:
            found.append((pathlib.Path(folder) / name).relative_to(ROOT).as_posix())
    return sorted(found)


def is_source(name):
    path = ROOT / name
    if not path.is_file():
        return False
    if path.suffix in SOURCE_SUFFIXES:
        return True
    with path.open("rb") as handle:
        return handle.read(2) == b"#!"


def has_header(name):
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    texts = []
    for line in lines[:HEADER_LINES]:
        for leader in COMMENT_LEADERS:
            if line.startswith(leader):
                texts.append(line[len(leader):].strip())
                break
    return SPDX in texts and COPYRIGHT in texts


def licence_problems():
    problems = []
    licence = ROOT / "LICENSE"
    if not licence.is_file() or hashlib.sha256(licence.read_bytes()).hexdigest() != APACHE_2_0_SHA256:
        problems.append("LICENSE is not the Apache License 2.0 text")
    notice = ROOT / "NOTICE"
    if not notice.is_file() or COPYRIGHT not in notice.read_text(encoding="utf-8").splitlines():
        problems.append("NOTICE lacks the line %r" % COPYRIGHT)
    sources = [name for name in files() if is_source(name)]
    for name in sources:
        if name not in EXEMPT and not has_header(name):
            problems.append("%s: no licence header" % name)
    for name in sorted(EXEMPT):
        if name not in sources:
            problems.append("%s: exempt, but not a source file here" % name)
        elif has_header(name):
            problems.append("%s: exempt, but carries the header (remove it from EXEMPT)" % name)
    return problems


REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.+-]*)$")


def pin_problems():
    return pyca_problems() + noble_problems()


def pyca_problems():
    problems = []
    path = ROOT / PYCA_REQUIREMENTS
    if not path.is_file():
        return ["%s is missing" % PYCA_REQUIREMENTS]
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    requirements = 0
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        requirements += 1
        if not REQUIREMENT.match(parts[0]):
            problems.append("%s: %r is not pinned with ==" % (PYCA_REQUIREMENTS, parts[0]))
        hashes = [p for p in parts[1:] if re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", p)]
        if not hashes or len(hashes) != len(parts) - 1:
            problems.append("%s: %s has no --hash=sha256 or an option that is not one" % (PYCA_REQUIREMENTS, parts[0]))
    if requirements == 0:
        problems.append("%s names no requirement" % PYCA_REQUIREMENTS)
    return problems


def noble_problems():
    problems = []
    path = ROOT / NOBLE_LOCK
    if not path.is_file():
        return ["%s is missing" % NOBLE_LOCK]
    packages = json.loads(path.read_text(encoding="utf-8")).get("packages", {})
    deps = {key: value for key, value in packages.items() if key}
    if not deps:
        problems.append("%s names no package" % NOBLE_LOCK)
    for key, value in sorted(deps.items()):
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(value.get("version", ""))):
            problems.append("%s: %s has no exact version" % (NOBLE_LOCK, key))
        if not str(value.get("integrity", "")).startswith("sha512-"):
            problems.append("%s: %s has no sha512 integrity" % (NOBLE_LOCK, key))
    return problems


def main():
    problems = licence_problems() + pin_problems()
    for problem in problems:
        print("FAIL " + problem)
    print("licence and pins: %s" % ("PASS" if not problems else "FAIL (%d)" % len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
