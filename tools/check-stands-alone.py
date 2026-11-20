# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Checks that this repository stands alone: that no file points a reader at something the reader cannot open.
Standard library only; reads files, writes nothing.

  python3 -B -I tools/check-stands-alone.py     exit 0 when every check holds, 1 when one does not (each is printed)

Read in every text file of this repository:

1. the private tree: the application name of the issuing server, an Elixir source file that is not a file of this
   repository, an Elixir function written as Module.function/arity whose module is neither defined here nor part of
   Elixir itself; and a reference to the issuing server's tree: a path under one of its top folders, or one of the
   server's own commands. Every run of path characters that holds a slash is read, whatever it starts with (a
   folder name, one or two dots, a slash, a tilde, a variable, the name of a repository). The reference is the run
   from its first piece that is one of those folders and has a piece after it. It is kept when the whole run is a
   path of this repository (whole, or a part of one) or is listed; or when the reference is, and no piece before it
   is the name of the server's repository;
2. a place on one machine: a home directory (its absolute path, a tilde path, the HOME variable), a private working
   folder;
3. the project's internal workflow: its reference numbers (one of its letter prefixes, a hyphen and digits), its
   names for a line of work, its words for merging a change and for a group of changes. A reference number is
   kept in two places only: inside the `hands` label of a signed payload, which is under the record's signature,
   and where README.md quotes that label as signed, in backticks, before its first section and in its correction
   note: the quotation holds the label, or the `hands` member with the label as its value, and nothing else. A
   quotation that holds anything more is read whole. Anywhere else the same characters are reported, the label's
   too;
4. a secret-shaped string, of the shapes a secret scanner stops an upload for.

And one check of what is said about the record published here:

5. the record was approved by two approver accounts, and its signed `hands` label says that one person operated
   them. No file may say, in the wordings APPROVED_BY_TWO lists, that the approvals were made by more than a single
   human:
   a person noun (persons, people, humans, individuals, men, women, approvers) after a word that counts more than
   one (two, both, a pair or couple of, multiple, several, many, more than one) or sets one apart from another
   (second, another, other, different, separate, distinct, independent); a compound of two or four with man,
   person, party or eyes; "dual" right before control, approval or authorisation; approvers said to be named.
   Every hyphen and dash is read as a hyphen, every space as a space, and a paragraph is read whole, across its
   line breaks. One sentence of README.md that says the opposite is kept, word for word. Wordings outside these
   classes are not found. And README.md must say, before its first section, that one person operated both accounts, quoting the label as signed, and say it
   again in the list of what a pass does not prove. The label is read from the record files, so the page is held to
   the signed bytes.

What is kept is listed below, each entry with its reason, and every list is exact: an entry that no longer matches
anything is reported, so an entry cannot outlive its reason. Before the files are read, the checks are run over one
planted line of each kind; a check that no longer finds its planted line is reported too. A check of build-machine
names runs before publication, outside this repository.

Every pattern is written in pieces, so that this file does not match itself; the names it refuses that are
themselves private are held only as SHA-256 digests, so that this file does not spell them. The file list is `git ls-files` in a
git checkout, and every file under this folder otherwise (a release archive)."""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parent.parent

PRIVATE_APP = re.compile("autonomous" + "_agency|Autonomous" + "Agency")
ELIXIR_FILE = re.compile(r"(?<![A-Za-z0-9_.])[A-Za-z0-9_.]*[A-Za-z0-9_]\.e" + r"xs?(?![A-Za-z0-9_])")
ELIXIR_FUNCTION = re.compile(r"(?<![A-Za-z0-9_.])([A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)*)\.[a-z_][a-z0-9_]*[!?]?/[0-9]"
                             r"(?![0-9A-Za-z])")
MODULE_DEFINED = re.compile(r"^\s*defmodule\s+([A-Z][A-Za-z0-9.]*)\s+do\b", re.M)
# modules of Elixir itself that this repository's pages name a function of
ELIXIR_OWN_MODULES = {"IO", "String"}
# the top folders of the issuing server's tree
SERVER_FOLDERS = {".github", "artifacts", "assets", "bench", "bin", "config", "docs", "lab", "lib", "ops", "priv",
                  "rel", "scripts", "test", "toolchain", "tools", "vectors"}
# The names of the server's repository: its public name, and the private name of its repository held as the SHA-256
# of the name as normalised_name writes it.
SERVER_REPOSITORIES = {"requisition"}
SERVER_REPOSITORY_DIGESTS = {"c258b0e237e78f7e3f74835b8b7a7282bff76a2dc183470d242af0bc82866fb0"}
# The one top folder of that tree whose name holds a space, so no run of path characters can hold it: (the SHA-256 of
# its name as normalised_name writes it, the length of that name). A line names it when, read as normalised_name
# reads it, the characters of that length right before a "/" or a "\" have that digest.
SPACED_FOLDER_DIGESTS = {("aa0bdb8356181453d274be58d85995a0354a00d9772404af6dd9cb32d48d4ebd", 14)}
# every run of spaces, underscores, hyphens and dashes, a "%20" and a backslash before a space
NAME_SEPARATORS = re.compile(r"(?:\\ |%20|[\s_\u2010-\u2015-])+")
PATH_RUN = re.compile(r"[A-Za-z0-9_.~$@+{}<>/-]+")
SERVER_COMMAND = re.compile(r"\bmi" + r"x requisition\.[a-z_.]+")
# the absolute path; a tilde and a slash where a word starts, with or without a user name between them (one letter
# between them is an Elixir sigil, and is kept); the HOME variable
HOME_PATH = re.compile(r"/ho" + r"me/|/Us" + r"ers/[A-Za-z0-9_.-]+|(?<![A-Za-z0-9_~])~(?:[A-Za-z0-9_.-]{2,})?" + r"/"
                       r"|\$\{?HO" + r"ME\b")
PRIVATE_FOLDER = re.compile(r"\.scra" + r"tch-|proj" + r"ect-sanction")
WORKFLOW = re.compile("|".join([
    r"coordi" + r"nator", r"owner's" + r" go", r"owner" + r"-run", r"delta[- ]" + r"review", r"build" + r" review",
    r"review" + r"-r[0-9]", r"fix" + r" round", r"(?i:(?<![a-z])la" + r"ne[ _-]?[0-9])", r"PLAN" + r"\.md",
    r"HAND" + r"BACK", r"OWNER" + r"-GOS", r"RULES" + r"\.md", r"\bW1" + r"-[0-9]", r"GAP" + r"-[A-Z]+-[0-9]",
    r"\bREQ" + r"-[0-9]+", r"\bPLAT" + r"-[0-9]+", r"\bSCR" + r"-[0-9]+", r"\bG" + r"-[0-9]+", r"\bD" + r"-[0-9]+",
    r"(?i:\blan" + r"d(?:ing|ed)\b)", r"(?i:\bser" + r"ies\b)",
]))
SECRET_SHAPE = re.compile("sk_li" + "ve_[0-9A-Za-z]{8,}|(?<![0-9A-Z])A[KS]" + "IA[0-9A-Z]{16}(?![0-9A-Z])|"
                          "gh[pousr]" + "_[0-9A-Za-z]{20,}|xo" + "x[abprs]-[0-9A-Za-z-]{8,}")

# --- what is kept, and why ------------------------------------------------------------------------------------------
# Byte copies of files of other repositories (PROVENANCE.md gives each one's source and SHA-256). A copy is never
# edited here: its wording is corrected in its source, and the corrected file arrives with the next copy. Checks 1
# and 3 do not read them; checks 2 and 4 do.
PINNED_COPIES = {
    "verifier/lab-verify": "a copy of Requisition's file; its comments cite files of the issuing server's source tree",
    "verifier/verify_offline.py": "a copy of requisition-aws's file; its comments cite files of the issuing server's "
                                  "source tree",
}
# Paths that hold the name of a folder of the issuing server's tree and are files a reader can open elsewhere, or
# files of a system or of a tool's own install folder. Each is used by a file here, and none is a path of this
# repository.
KEPT_PATHS = {
    "bi" + "n/lab-verify": "Requisition's lab record checker, the source of verifier/lab-verify (PROVENANCE.md)",
    "bi" + "n/verify_offline.py": "a file of the public requisition-aws repository, the source of "
                                  "verifier/verify_offline.py",
    "bi" + "n/verify_chain.py": "a file of the public requisition-aws repository",
    "bi" + "n/vendor/mldsa.py": "a file of the public requisition-aws repository, the source of verifier/mldsa.py",
    "li" + "b/libbotan-3.a": "a file of a Botan install folder (interop/verifiers/botan/compile.sh)",
    "li" + "b/libcrypto.a": "a file of an AWS-LC install folder (interop/verifiers/aws-lc/compile.sh)",
    "li" + "b/libwolfssl.a": "a file of a wolfSSL install folder (interop/verifiers/wolfssl/compile.sh)",
    "/usr/bi" + "n/env": "the system's env, in the first line of a program",
    "/bi" + "n/sh": "the system's shell, in the first line of a script",
    "$WORK/go/bi" + "n/go": "the Go tool of a Go install folder the reader makes (interop/verifiers/go-crypto-mldsa/)",
    "$WORK/pyca/bi" + "n/pip": "pip of a virtual environment the reader makes (interop/verifiers/pyca-cryptography/)",
    "$WORK/pyca/bi" + "n/python": "the Python of the same virtual environment",
}
# A folder of the issuing server's tree that a page here names as the source of byte copies: {source folder: (the
# pages that may name it, the folders of the copies here, why)}. Such a page may name the folder itself, and a file
# under it only when the file of the same name is under one of the folders of the copies.
SOURCE_FOLDERS = {
    "la" + "b/checkpoint-vectors": (("PROVENANCE.md",), ("checkpoint-vectors",),
                                    "the page gives the source of every copied vector file, row by row"),
    "ben" + "ch/holytrinity-v2/verifier": (("PROVENANCE.md", "CHECKPOINTS.md"), ("verifier", "elixir", "elixir/sources"),
                                          "PROVENANCE.md gives the source of every copied file of the receipt "
                                          "verifier, row by row; CHECKPOINTS.md, a copy of requisition-aws's page, "
                                          "says where that verifier's own page is"),
}
# Byte copies whose text names such a path and that checks 1 and 3 read: this rule does not read them.
PATH_COPIES = {
    "verifier/CHECKPOINTS.md": "a copy of the public receipt-verification release's page; it names the source "
                               "folder of the vectors",
    "elixir/CHECKPOINTS.md": "the same page, in the Hex package",
    "elixir/VERDICTS.md": "a copy of the public receipt-verification release's page of verdicts, in the Hex package; "
                          "one line cites a page of the issuing server's source tree",
}
# The `hands` label that the evaluation environment signs into every record carries a reference number. Check 3
# does not read the label where it is signed (the `hands` member of a `signed_payload`, once per payload), nor a
# backtick quotation of exactly the label of the two records published here, as signed, in README.md's opening and
# correction note.
QUOTATION = re.compile(r"`[^`\n]*`")
# The key file exactly as the evaluation environment served it: the `note` member of three of its entries carries
# a reference number, and names the command that made the key. The file is the published evidence the record is
# checked against; it is not rewritten.
FROZEN_FILES = {"record/public-keys.json": "the published key file, byte for byte as served; three `note` members"}


# --- check 5 ----------------------------------------------------------------------------------------------------------
# The classes of wording (the docstring, check 5): a person noun after a word that counts more than one or sets one
# apart from another, with at most three words between and not right after "one" (but after "than one") or "single"; a
# compound of two or
# four with man, person, party or eyes; "dual" right before control, approval or authorisation; approvers said to be
# named. Read on text that
# normalise() has made: every hyphen and dash a "-", every space a " ", a paragraph's lines joined. The true sentences
# say "accounts" and "one person", which none of these reads.
PERSONS = r"(?:per" + r"sons?|peo" + r"ple|humans?|individuals?|men|women|appro" + r"vers)"
MORE_THAN_ONE = (r"(?:two|2|both|pair\s+of|couple\s+of|multiple|several|many|more\s+than\s+one|second|another|other"
                 r"|different|separate|distinct|independent)")
APPROVED_BY_TWO = re.compile(
    r"(?i)\b" + MORE_THAN_ONE + r"(?:[\s-]+[a-z]+){0,3}?[\s-]+(?:(?<=\bthan one )|(?<!\bone )(?<!\bone-)(?<!\bsingle ))" + PERSONS + r"\b"
    + r"|\b(?:two|four|2|4|dual|double)[\s-]*(?:m" + r"an|m" + r"en|per" + r"sons?|peo" + r"ple|par" + r"ty|par" + r"ties"
    + r"|e" + r"yes|e" + r"yed)\b"
    + r"|\bdual[\s-]+(?:con" + r"trol|appro" + r"val|authori[sz]ation|sign[\s-]?off)\b"
    + r"|named appro" + r"vers\b")
# every hyphen and dash, and every space, in the forms a page may write them
DASHES = re.compile("[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]")
SPACES = re.compile("[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]")
# characters that show nothing: zero-width space, non-joiner and joiner, word joiner, byte-order mark
ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060\ufeff]")


def normalise(text):
    """The text as the wording rule reads it: each hyphen or dash a "-", each space a " ", soft hyphens and zero-width
    characters removed."""
    return SPACES.sub(" ", DASHES.sub("-", ZERO_WIDTH.sub("", text.replace("\u00ad", ""))))
RECORDS = ("record/statement.json", "record/decision.json")
ONE_PERSON = "one-per" + "son"
OPENING_SAYS = "operated by one per" + "son"
PAGE = "README.md"
# the line that opens the page's list of what a pass does not prove; the list ends at the next section
LIMITS_OPEN = "A pass does not pro" + "ve"
# The one place that may quote the wording: the dated note in README.md that corrects what the v0.1.0 tag message
# and page title said. Check 5 does not read the lines of that section.
CORRECTION_HEADING = "## Correction (2026-11-19)"
# A pinned copy whose text says the opposite ("NOT two ..."): the label does not show more than a single human.
SAYS_THE_OPPOSITE = {"verifier/lab-verify": "a copy of Requisition's file; its two lines say what the label does NOT show"}
# The one sentence of the page that states the opposite, kept word for word (the list of what a pass does not prove);
# the same words without their "not" are refused like any other.
KEPT_SENTENCES = {PAGE: ("The two approvals were not made by two independent per" + "sons.",)}


def files():
    if (ROOT / ".git").exists():
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
        return sorted(name for name in out.decode("utf-8").split("\0") if name)
    found = []
    for folder, _dirs, names in os.walk(ROOT):
        for name in names:
            found.append((pathlib.Path(folder) / name).relative_to(ROOT).as_posix())
    return sorted(found)


def texts():
    """(name, text) of every file that is UTF-8 text."""
    out = []
    for name in files():
        path = ROOT / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            out.append((name, data.decode("utf-8")))
        except UnicodeDecodeError:
            continue
    return out


def private_tree(text, own_files, own_modules):
    """[(line number, what)] for check 1."""
    hits = []
    for number, line in enumerate(text.split("\n"), 1):
        if PRIVATE_APP.search(line):
            hits.append((number, "the issuing server's application name"))
        if any(found.rsplit("/", 1)[-1] not in own_files for found in ELIXIR_FILE.findall(line)):
            hits.append((number, "an Elixir source file that is not in this repository"))
        if any(module not in own_modules and module not in ELIXIR_OWN_MODULES
               for module in ELIXIR_FUNCTION.findall(line)):
            hits.append((number, "an Elixir function of a module that is not in this repository"))
    return hits


def own_paths(names):
    """Every path of this repository, every folder, and every end of one ("a/b/c" gives a/b/c, b/c, c, a/b, b, a)."""
    own = set()
    for name in names:
        parts = name.split("/")
        for start in range(len(parts)):
            for end in range(start + 1, len(parts) + 1):
                own.add("/".join(parts[start:end]))
    return own


def normalised_name(text):
    """`text` as the private names are compared: NFKC, lower case, and every run of NAME_SEPARATORS one "-"."""
    return NAME_SEPARATORS.sub("-", unicodedata.normalize("NFKC", text).lower())


def name_digest(name):
    return hashlib.sha256(normalised_name(name).encode("utf-8")).hexdigest()


def server_repository(piece, repositories):
    """Whether one piece of a path is the name of the server's repository."""
    return normalised_name(piece) in SERVER_REPOSITORIES or name_digest(piece) in repositories


def spaced_folder_hit(digest):
    return "a folder of the issuing server's source tree, by its digest " + digest[:12]


def spaced_folders_in(line, folders):
    """The digest of every listed folder `line` names, once for each place it names it."""
    normal = normalised_name(line)
    return [digest for slash in re.finditer(r"[/\\]", normal) for digest, length in sorted(folders)
            if slash.start() >= length
            and hashlib.sha256(normal[slash.start() - length:slash.start()].encode("utf-8")).hexdigest() == digest]


def references(text, repositories=None):
    """[(line number, the whole run, the reference, whether a piece before it names the server's repository)] for
    every run of path characters that holds a top folder of the issuing server's tree with a piece after it. The
    digests of the repository's private names are the check's own unless others are given."""
    repositories = SERVER_REPOSITORY_DIGESTS if repositories is None else repositories
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        for run in PATH_RUN.findall(line):
            if "/" not in run:
                continue
            pieces = run.rstrip("./-").split("/")
            while pieces and pieces[0] in (".", ".."):
                pieces = pieces[1:]
            start = next((i for i in range(len(pieces) - 1) if pieces[i] in SERVER_FOLDERS and pieces[i + 1]), None)
            if start is not None:
                found.append((number, "/".join(pieces), "/".join(pieces[start:]),
                              any(server_repository(piece, repositories) for piece in pieces[:start])))
    return found


def source_copy(name, token, own, sources):
    """The source folder `token` is in, when `name` is a page that may name that folder and the copy is here."""
    for folder, (pages, copies, _why) in sources.items():
        if name in pages and (token == folder or (token.startswith(folder + "/") and any(
                copy + token[len(folder):] in own for copy in copies))):
            return folder
    return None


def server_tree(name, text, own, kept=None, sources=None, used=None, repositories=None, folders=None):
    """[(line number, what)] for the second half of check 1. `used` gathers the listed paths, and the (source
    folder, page) pairs, that kept something. The digest tables are the check's own unless others are given."""
    kept = KEPT_PATHS if kept is None else kept
    folders = SPACED_FOLDER_DIGESTS if folders is None else folders
    sources = SOURCE_FOLDERS if sources is None else sources
    used = set() if used is None else used
    hits = []
    for number, whole, reference, named in references(text, repositories):
        if whole in own:
            continue
        if whole in kept:
            used.add(whole)
        elif not named and reference in own:
            continue
        elif not named and reference in kept:
            used.add(reference)
        elif not named and source_copy(name, reference, own, sources):
            used.add((source_copy(name, reference, own, sources), name))
        else:
            hits.append((number, "a path of the issuing server's source tree: " + (whole if named else reference)))
    for number, line in enumerate(text.split("\n"), 1):
        hits.extend((number, spaced_folder_hit(digest)) for digest in spaced_folders_in(line, folders))
        hits.extend((number, "a command of the issuing server: " + found) for found in SERVER_COMMAND.findall(line))
    return hits


def one_machine(text):
    """[(line number, what)] for check 2."""
    hits = []
    for number, line in enumerate(text.split("\n"), 1):
        if HOME_PATH.search(line):
            hits.append((number, "a home directory"))
        if PRIVATE_FOLDER.search(line):
            hits.append((number, "a private working folder"))
    return hits


def workflow(text):
    """[(line number, the words found)] for check 3."""
    hits = []
    for number, line in enumerate(text.split("\n"), 1):
        found = [match.group(0) for match in WORKFLOW.finditer(line)]
        if found:
            hits.append((number, "internal workflow wording: " + ", ".join(sorted(set(found)))))
    return hits


def signed_payloads(text):
    """The string value of every `signed_payload` member of a JSON text, at any depth; [] when it is not JSON."""
    try:
        queue = [json.loads(text)]
    except ValueError:
        return []
    found = []
    while queue:
        item = queue.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "signed_payload" and isinstance(value, str):
                    found.append(value)
                else:
                    queue.append(value)
        elif isinstance(item, list):
            queue.extend(item)
    return found


def hands_of(payload):
    """The `hands` label of one signed payload, or None."""
    try:
        metadata = json.loads(payload).get("metadata")
    except (ValueError, AttributeError):
        return None
    hands = metadata.get("hands") if isinstance(metadata, dict) else None
    return hands if isinstance(hands, str) else None


def without_signed_labels(text):
    """A record file as check 3 reads it: the `hands` member of each signed payload is blanked where it stands in
    the file, once per payload. The member is looked for as the record files write it (compact JSON inside a JSON
    string); written any other way it is not found, and its reference number is reported."""
    for payload in signed_payloads(text):
        label = hands_of(payload)
        if label is not None:
            member = json.dumps({"hands": label}, separators=(",", ":"))[1:-1]
            text = text.replace(json.dumps(member)[1:-1], " ", 1)
    return text


def quoted_as_signed(label):
    """The backtick quotations that quote `label` exactly as signed: the label alone, bare or in its quotation
    marks, or the `hands` member that holds it, as JSON writes the member with or without a space."""
    member = json.dumps({"hands": label})[1:-1]
    compact = json.dumps({"hands": label}, separators=(",", ":"))[1:-1]
    return {"`%s`" % quoted for quoted in (label, json.dumps(label), member, compact)}


def without_quoted_labels(text, labels):
    """README.md as check 3 reads it: before the first section and in the correction note, a backtick quotation
    that is exactly one of `labels` as signed (the labels signed in the record files) is blanked. A quotation that
    holds a label and anything more is left as it is, so every reference number in it is reported."""
    exact = set().union(*[quoted_as_signed(label) for label in labels]) if labels else set()
    lines, kept_here = [], True
    for line in text.split("\n"):
        if line.startswith("## "):
            kept_here = line.strip() == CORRECTION_HEADING
        if kept_here:
            line = QUOTATION.sub(lambda quoted: " " if quoted.group(0) in exact else quoted.group(0), line)
        lines.append(line)
    return "\n".join(lines)


def outside_correction(name, text):
    """The lines of `text` as (number, line), without the correction note's section when the file is the page."""
    lines, inside = [], False
    for number, line in enumerate(text.split("\n"), 1):
        if name == PAGE and line.startswith("## "):
            inside = line.strip() == CORRECTION_HEADING
        if not inside:
            lines.append((number, line))
    return lines


def without_kept(name, line):
    """The line without the sentences KEPT_SENTENCES keeps in this file, each word for word."""
    for sentence in KEPT_SENTENCES.get(name, ()):
        line = line.replace(sentence, " ")
    return line


def paragraphs(lines):
    """[(first line number, text)]: each run of lines that are not blank, joined by a space. A blank line holds only
    spaces and tabs (and the carriage return of a CRLF line end), as a Markdown page reads one: a line holding a form feed, or another control character, does not
    end a paragraph."""
    found, run = [], []
    for number, line in lines + [(None, "")]:
        if line.strip(" \t\r"):
            run.append((number, line))
        elif run:
            found.append((run[0][0], " ".join(text.strip() for _number, text in run)))
            run = []
    return found


def approved_by_two(name, text):
    """[(line number, what)] for check 5's wording rule: every match in every paragraph, read whole, named by the
    paragraph's first line."""
    found = []
    for number, paragraph in paragraphs(outside_correction(name, normalise(text))):
        for match in APPROVED_BY_TWO.finditer(without_kept(name, paragraph)):
            found.append((number, "says the approvals were made by more than one hu" + "man: %r" % match.group(0)))
    return found


def limits_of(page):
    """The page's list of what a pass does not prove: from the line that opens it to the next section. None when
    no line opens it."""
    parts = ("\n" + page).split("\n" + LIMITS_OPEN, 1)
    return parts[1].split("\n## ", 1)[0] if len(parts) == 2 else None


def signed_hands():
    """The `hands` label of every signed payload in the record files, as signed."""
    labels = set()
    for name in RECORDS:
        for payload in signed_payloads((ROOT / name).read_text(encoding="utf-8")):
            if hands_of(payload) is not None:
                labels.add(hands_of(payload))
    return labels


def record_problems(all_texts):
    """Check 5 over the files: the wording rule, the page's opening, and the lists of what is kept."""
    found = []
    by_name = dict(all_texts)
    for name, text in all_texts:
        hits = approved_by_two(name, text)
        if name in SAYS_THE_OPPOSITE:
            if not hits:
                found.append("%s: listed in SAYS_THE_OPPOSITE, and no line of it has the wording (remove it)" % name)
            continue
        found.extend("%s:%d: %s" % (name, number, what) for number, what in hits)
    for name in sorted(set(SAYS_THE_OPPOSITE) - set(by_name)):
        found.append("%s: listed in SAYS_THE_OPPOSITE, and is not a text file here" % name)
    for name, sentences in sorted(KEPT_SENTENCES.items()):
        for sentence in sentences:
            if sentence not in by_name.get(name, ""):
                found.append("%s: KEPT_SENTENCES keeps %r, and the file does not say it (remove it)" % (name, sentence))
    labels = signed_hands()
    if not labels:
        found.append("no signed `hands` label was read from %s" % " and ".join(RECORDS))
    page = by_name.get(PAGE, "")
    opening = page.split("\n## ", 1)[0]
    for label in sorted(label for label in labels if label.startswith(ONE_PERSON)):
        if OPENING_SAYS not in opening or label not in opening:
            found.append("%s: before its first section the page does not say that both approver accounts were %s, "
                         "quoting the signed label %r" % (PAGE, OPENING_SAYS, label))
    if any(label.startswith(ONE_PERSON) for label in labels):
        limits = limits_of(page)
        if limits is None:
            found.append("%s: no line opens the list of what a pass does not prove (%r)" % (PAGE, LIMITS_OPEN))
        elif OPENING_SAYS not in limits:
            found.append("%s: the list of what a pass does not prove does not say that both approver accounts were "
                         "%s" % (PAGE, OPENING_SAYS))
    note = [line for line in page.split("\n") if line.strip() == CORRECTION_HEADING]
    if len(note) != 1:
        found.append("%s: the section %r is there %d time(s), expected once" % (PAGE, CORRECTION_HEADING, len(note)))
    elif len(approved_by_two(PAGE, page)) == len([1 for line in page.split("\n") if APPROVED_BY_TWO.search(line)]):
        found.append("%s: the section %r quotes none of the wording it is kept for" % (PAGE, CORRECTION_HEADING))
    return found


def problems():
    found = []
    all_texts = texts()
    own_files = {name.rsplit("/", 1)[-1] for name in files()}
    own_modules = set()
    for name, text in all_texts:
        if name.endswith((".ex", ".exs")):
            own_modules.update(MODULE_DEFINED.findall(text))
    frozen_seen = set()
    labels = signed_hands()
    own = own_paths(files())
    paths_used, copies_seen = set(), set()
    for name, text in all_texts:
        tree = private_tree(text, own_files, own_modules)
        read_here = name not in PATH_COPIES and name not in PINNED_COPIES and name not in FROZEN_FILES
        paths = server_tree(name, text, own, used=paths_used if read_here else set())
        if name in PATH_COPIES:
            if paths:
                copies_seen.add(name)
            paths = []
        elif not read_here:
            paths = []
        tree = tree + paths if name not in PINNED_COPIES else tree
        words = workflow(without_quoted_labels(text, labels) if name == PAGE else without_signed_labels(text))
        if name in PINNED_COPIES:
            if not tree:
                found.append("%s: listed as a pinned copy that names the private tree, and names nothing "
                             "(remove it from PINNED_COPIES)" % name)
            tree, words = [], []
        if name in FROZEN_FILES:
            if words:
                frozen_seen.add(name)
            words = []
        hits = tree + one_machine(text) + words
        if SECRET_SHAPE.search(text):
            hits.append((0, "a secret-shaped string"))
        for number, what in sorted(hits):
            found.append("%s:%d: %s" % (name, number, what))
    names = {name for name, _text in all_texts}
    for name in sorted(set(PINNED_COPIES) | set(FROZEN_FILES)):
        if name not in names:
            found.append("%s: listed as kept, and is not a text file here" % name)
    for name in sorted(set(FROZEN_FILES) & names - frozen_seen):
        found.append("%s: listed as a frozen file with a reference number, and carries none (remove it from "
                     "FROZEN_FILES)" % name)
    for token in sorted(KEPT_PATHS):
        if token not in paths_used:
            found.append("%s: listed in KEPT_PATHS, and no file names it (remove it)" % token)
        if token in own:
            found.append("%s: listed in KEPT_PATHS, and is a path of this repository (remove it)" % token)
    for folder, (pages, _copies, _why) in sorted(SOURCE_FOLDERS.items()):
        for page in pages:
            if (folder, page) not in paths_used:
                found.append("%s: listed in SOURCE_FOLDERS, and %s does not name it (remove the page)" % (folder, page))
    for name in sorted(PATH_COPIES):
        if name not in names:
            found.append("%s: listed in PATH_COPIES, and is not a text file here" % name)
        elif name not in copies_seen:
            found.append("%s: listed in PATH_COPIES, and names no such path (remove it)" % name)
    return found + record_problems(all_texts)


def planted_problems():
    """Each check over one planted line of its kind, and over lines it must not report."""
    app, source, function = "autonomous" + "_agency", "lab_key_rule" + ".ex", "LabKeyRule" + ".standing/3"
    own_files, own_modules = {"mine" + ".exs"}, {"Mine.Module"}
    label = "one-per" + "son (G" + "-301)"
    payload = json.dumps({"metadata": {"hands": label}}, separators=(",", ":"))
    record = json.dumps({"signed_payload": payload, "signature": "AA=="}, indent=1)
    record_and_note = json.dumps({"signed_payload": payload, "note": "see G" + "-301"}, indent=1)
    # the opening and the correction note may quote exactly the label as signed, in backticks; lines 2 and 4 are
    # reported
    page = ("the label says `\"hands\": \"" + label + "\"`\nand without backticks: " + label + "\n## A section\n"
            "quoted here too: `" + label + "`\n" + CORRECTION_HEADING + "\nit said `" + label + "`")
    # a quotation that holds the label and anything more is read whole: every line of these is reported, in the
    # opening and in the correction note
    more = ["`" + label + " per SC" + "R-1513`", "`" + label + " means one operator`", "`\"hands\": \"" + label + "\", see G" + "-302`",
            "`hands: " + label + "`", "`" + label + "` and `SC" + "R-1513`"]
    exact = ["`" + label + "`", "`\"" + label + "\"`", "`\"hands\":\"" + label + "\"`", "`\"hands\": \"" + label + "\"` and `a word`"]
    cases = [
        (private_tree("lib/" + app + "/x", own_files, own_modules), 1), (private_tree("see " + source, own_files, own_modules), 1),
        (private_tree("a.b." + source, own_files, own_modules), 1), (private_tree("as " + function + " does", own_files, own_modules), 1),
        (private_tree("kept: mine" + ".exs, Mine.Module" + ".run/1, IO.puts/1, a/b 1/2, index.exe", own_files, own_modules), 0),
        (one_machine("/ho" + "me/someone/x"), 1), (one_machine("/ho" + "me/$USER"), 1),
        (one_machine(".scra" + "tch-2026-01-01/x"), 1), (one_machine("a folder of this repository"), 0),
        (one_machine("see ~" + "/requisition/x"), 1), (one_machine("cd ~" + "/"), 1), (one_machine("in ~someone" + "/work"), 1),
        (one_machine("$HO" + "ME/work"), 1), (one_machine("${HO" + "ME}/work"), 1), (one_machine('"$HO' + 'ME"'), 1),
        (one_machine("~r" + "/[0-9]+/ and ~s" + "/a/, a ~ b / c, x~" + "/y, $HOMEBREW_PREFIX, at home"), 0),
        (workflow("see RE" + "Q-171"), 1), (workflow("la" + "ne 2a"), 1), (workflow("in this lan" + "ding"), 1),
        (workflow("the fix ser" + "ies"), 1), (workflow("G" + "-302"), 1), (workflow("SC" + "R-1500"), 1),
        (workflow("PL" + "AT-083"), 1), (workflow("see D" + "-29"), 1), (workflow("G" + "-7"), 1),
        (workflow("an island, a serious error, ML-DSA-87, RFC-8785, SHA-256, ID-1"), 0),
        # a reference number is reported wherever it is not the signed label itself, or the page's quotation of it
        (workflow("see G" + "-301 for the rule"), 1), (workflow("hands: " + label), 1),
        (workflow(without_signed_labels(record)), 0), (workflow(without_signed_labels(record_and_note)), 1),
        (workflow(without_signed_labels("the label " + label + " in a file that is not a record")), 1),
        (workflow(without_quoted_labels(page, {label})), 2), (workflow(page), 4),
        (workflow(without_quoted_labels("\n".join(more), {label})), len(more)),
        (workflow(without_quoted_labels(CORRECTION_HEADING + "\n" + "\n".join(more), {label})), len(more)),
        (workflow(without_quoted_labels("\n".join(exact), {label})), 0),
        (workflow(without_quoted_labels("## A section\n" + "\n".join(exact), {label})), len(exact)),
    ]
    own = own_paths(["bi" + "n/mine.py", "kept/copies/a.json"])
    source = {"la" + "b/vecto" + "rs": (("PAGE.md",), ("elsewhere", "kept/copies"), "planted")}
    one = ["run bi" + "n/scratch-db first", "registered from `la" + "b/seed/demo.v1.json`.",
           "reads $DIR/req/la" + "b/seed/demo.v1.json", "# as li" + "b/server/rule does", "(pri" + "v/repo/migrations)",
           "see confi" + "g/runtime", "its tes" + "t/support/fixtures/x folder", "run script" + "s/serve first",
           "run `mi" + "x requisition.lab.seed --set x`", "the public bi" + "n/tool.py of another repository",
           # every form of a reference: after one or two dots, a slash, a folder, a variable, the repository's
           # name, a tilde
           "run ./bi" + "n/scratch-db --keep first", "run ../bi" + "n/scratch-db first", "run requisition/bi" + "n/scratch-db first",
           "see ~" + "/requisition/bi" + "n/gate", "see $HO" + "ME/work/bi" + "n/gate", "[the page](/do" + "cs/internal/page.md)",
           "$CHECKOUT/op" + "s/runbook.md", "the file of another checkout: requisition/bi" + "n/mine.py",
           "#!/usr/bi" + "n/env python3", "$PREFIX/li" + "b/libx.a", "/usr/li" + "b/x"]
    # and every top folder of that tree, written out here: a folder taken out of SERVER_FOLDERS, or put into it, is
    # reported
    folders = [".git" + "hub", "artifa" + "cts", "asse" + "ts", "ben" + "ch", "bi" + "n", "confi" + "g", "do" + "cs", "la" + "b",
               "li" + "b", "op" + "s", "pri" + "v", "re" + "l", "script" + "s", "tes" + "t", "toolcha" + "in", "too" + "ls", "vecto" + "rs"]
    one += ["see " + folder + "/" + "internal/x.md" for folder in folders]
    none = ["run bi" + "n/mine.py", "run ./bi" + "n/mine.py", "the file /path/to/bi" + "n/mine.py",
            "the copies kept/copies/a.json and copies/a.json", "requisition-la" + "b:account:x", "POST /v1/la" + "b-keys",
            "mi" + "x test", "a mi" + "x of requisition records", "verifier/lab-verify", "the bi" + "n/ folder",
            "a do" + "cs/ folder, and li" + "b/", "application/json", "a/b ratio 1/2"]
    cases += [(server_tree("x.md", line, own, {}, {}), 1) for line in one]
    cases += [(server_tree("x.md", line, own, {}, {}), 0) for line in none]
    listed = {"bi" + "n/tool.py": "listed", "/usr/bi" + "n/env": "the system's"}
    cases += [
        (server_tree("x.md", "the public bi" + "n/tool.py of another repository", own, listed, {}), 0),
        (server_tree("x.md", "the public /path/to/bi" + "n/tool.py and #!/usr/bi" + "n/env", own, listed, {}), 0),
        (server_tree("x.md", "requisition/bi" + "n/tool.py", own, listed, {}), 1),
        (server_tree("x.md", "x/usr/bi" + "n/env", own, listed, {}), 1),
        # a source folder is kept on its pages, and a file under it only when its copy is here
        (server_tree("PAGE.md", "from `la" + "b/vecto" + "rs/`, `../la" + "b/vecto" + "rs/` and `la" + "b/vecto" + "rs/a.json`", own, {}, source), 0),
        (server_tree("PAGE.md", "from `la" + "b/vecto" + "rs/b.json`", own, {}, source), 1),
        (server_tree("PAGE.md", "from `requisition/la" + "b/vecto" + "rs/a.json`", own, {}, source), 1),
        (server_tree("OTHER.md", "from `la" + "b/vecto" + "rs/a.json`", own, {}, source), 1),
    ]
    found = ["the planted line of case %d was reported %d time(s), expected %d" % (index, len(hits), expected)
             for index, (hits, expected) in enumerate(cases) if len(hits) != expected]
    if sorted(folders) != sorted(SERVER_FOLDERS):
        found.append("SERVER_FOLDERS is not the list of top folders the planted lines are written for")
    page = "a two-per" + "son approval\n" + CORRECTION_HEADING + "\nit said two-per" + "son\n## Next\nTwo Peo" + "ple approved"
    for index, (hits, expected) in enumerate([
            (approved_by_two(PAGE, page), 2), (approved_by_two("other.md", page), 3),
            (approved_by_two("x.md", "the named appro" + "vers"), 1),
            (approved_by_two("x.md", "two approver accounts, operated by one person; two personal keys"), 0),
            # other wordings of the same claim, not only its three spellings
            (approved_by_two("x.md", "The two approvals were made by two independent per" + "sons."), 1),
            (approved_by_two("x.md", "approved by 2 peo" + "ple"), 1),
            (approved_by_two("x.md", "the approvals came from different peo" + "ple"), 1),
            (approved_by_two("x.md", "a second per" + "son approved it"), 1),
            (approved_by_two("x.md", "two separate huma" + "ns signed off"), 1),
            (approved_by_two("x.md", "approved by independent peo" + "ple"), 1),
            (approved_by_two("x.md", "by distinct per" + "sons"), 1),
            (approved_by_two("x.md", "made by separate individ" + "uals"), 1),
            (approved_by_two("x.md", "Both approver accounts were operated by one person in this run."), 0),
            (approved_by_two("x.md", "held the request until it was approved by two separate accounts"), 0),
            # the same claim spelled with another hyphen or dash, broken across a line, or in other words
            (approved_by_two("x.md", "This record shows two\u2011per" + "son approval."), 1),
            (approved_by_two("x.md", "two\u2013per" + "son approval of the refund"), 1),
            (approved_by_two("x.md", "two\u2014peo" + "ple approved"), 1),
            (approved_by_two("x.md", "The refund was approved by two\npeo" + "ple before it ran."), 1),
            (approved_by_two("x.md", "approved by two\u00a0peo" + "ple"), 1),
            # a line holding only a form feed does not end a paragraph, and zero-width characters are not read
            (approved_by_two("x.md", "The refund was approved by two\n\f\npeo" + "ple before it ran."), 1),
            (approved_by_two("x.md", "two\u200bper" + "son approval"), 1),
            (approved_by_two("x.md", "two\u200cper" + "son approval"), 1),
            (approved_by_two("x.md", "two-\u200dper" + "son approval"), 1),
            (approved_by_two("x.md", "two\u2060per" + "son approval"), 1),
            (approved_by_two("x.md", "two\ufeffper" + "son approval"), 1),
            (approved_by_two("x.md", "A pair of peo" + "ple approved the refund."), 1),
            (approved_by_two("x.md", "The refund ran under a two-m" + "an rule."), 1),
            (approved_by_two("x.md", "The refund was released under the four-e" + "yes principle."), 1),
            (approved_by_two("x.md", "two different appro" + "vers signed it"), 1),
            (approved_by_two("x.md", "one person approved and another per" + "son confirmed"), 1),
            (approved_by_two("x.md", "approved by multiple peo" + "ple"), 1),
            (approved_by_two("x.md", "two-pa" + "rty approval"), 1),
            (approved_by_two("x.md", "dual con" + "trol: each approval by its own person"), 1),
            (approved_by_two("x.md", "Both approver accounts\nwere operated by one person in this run."), 0),
            (approved_by_two("x.md", "the relying party checks it; a third party holds no key"), 0),
            (approved_by_two("x.md", "the refund was approved by more than one per" + "son"), 1),
            (approved_by_two("x.md", "both accounts held by one person"), 0),
            (approved_by_two("x.md", "two accounts of a single person"), 0),
            (approved_by_two("x.md", "both by a single person"), 0),
            # the page's one kept sentence, word for word; without its "not"; and elsewhere
            (approved_by_two(PAGE, "- **" + KEPT_SENTENCES[PAGE][0] + "** Both accounts..."), 0),
            (approved_by_two(PAGE, KEPT_SENTENCES[PAGE][0].replace(" not ", " ")), 1),
            (approved_by_two("x.md", KEPT_SENTENCES[PAGE][0]), 1)]):
        if len(hits) != expected:
            found.append("check 5: the planted text of case %d was reported %d time(s), expected %d" % (index, len(hits), expected))
    limits = LIMITS_OPEN + " this:\n- both accounts were " + OPENING_SAYS + "\n## Next\nnothing"
    for index, (got, expected) in enumerate([
            (OPENING_SAYS in (limits_of("opening, " + OPENING_SAYS + "\n" + limits) or ""), True),
            (OPENING_SAYS in (limits_of(LIMITS_OPEN + " this:\n- a list\n## Next\n" + OPENING_SAYS) or ""), False),
            (limits_of("a page, " + OPENING_SAYS + ", without that list"), None)]):
        if got != expected:
            found.append("check 5: the planted page of case %d gave %r, expected %r" % (index, got, expected))
    for value in ("sk_li" + "ve_" + "a1B2c3D4e5", "AK" + "IA" + "Q" * 16, "gh" + "p_" + "a" * 36, "xo" + "xb-" + "1234-abcd"):
        if not SECRET_SHAPE.search("key = " + value):
            found.append("a planted secret-shaped string was not found: %s..." % value[:6])
    return found + planted_name_problems()


def planted_name_problems():
    """The private names, held as digests: the tables are well formed, and every generated form of two made-up names is
    found when the check is given their digests in place of its own tables, and found by its own tables never."""
    found = []
    for digest in sorted(SERVER_REPOSITORY_DIGESTS | {digest for digest, _length in SPACED_FOLDER_DIGESTS}):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            found.append("a digest of a private name is not 64 hexadecimal digits: %s" % digest)
    if not SERVER_REPOSITORY_DIGESTS or not SPACED_FOLDER_DIGESTS or any(length < 1 for _, length in SPACED_FOLDER_DIGESTS):
        found.append("a table of private names is empty, or a folder's length is not positive")
    # the form the digests are taken of: each separator run is one hyphen, in lower case, after NFKC
    if normalised_name("Ex\uff41mple \u00a0_Name%20x\\ y\u2011-z") != "example-name-x-y-z":
        found.append("a name is not normalised to the form its digest is taken of")
    repository, folder = "Example-Repository", "Example Folder"
    repositories, folders = {name_digest(repository)}, {(name_digest(folder), len(normalised_name(folder)))}
    (digest, _length), = folders
    own = own_paths(["bi" + "n/mine.py"])
    expected_folder = [(1, spaced_folder_hit(digest))]
    cases = lambda name: sorted({name, name.lower(), name.upper(), name.swapcase()})
    for spelled in cases(folder):
        for space in [" ", "  ", "_", "-", "%20", "\\ ", " ", "‑", " - "]:
            for before in ["", "in ", "x", "/", "./", "~" + "/", "a/b/", "`", "(", '"']:
                for after in ["/", "/notes.md", "\\", "\\notes.md"]:
                    line = before + spelled.replace(" ", space) + after
                    if server_tree("x.md", line, own, {}, {}, repositories=repositories, folders=folders) != expected_folder:
                        found.append("the planted folder name was not found once: %r" % line)
                    if server_tree("x.md", line, own, {}, {}) != []:
                        found.append("the check's own tables found a made-up folder name: %r" % line)
    for line in ["Example Folders/", "an Example Folder here", "Example Folder.md", "Example/Folder/", "ExampleFolder/",
                 "Example Folder", "an Example Folderx/", "Example Folder |"]:
        if server_tree("x.md", line, own, {}, {}, repositories=repositories, folders=folders) != []:
            found.append("a line that does not name the planted folder was reported: %r" % line)
    # the name in full-width letters is read as NFKC reads it
    wide = "".join(chr(ord(c) + 0xFEE0) if c != " " else c for c in folder) + "/"
    if server_tree("x.md", wide, own, {}, {}, repositories=repositories, folders=folders) != expected_folder:
        found.append("the planted folder name in full-width letters was not found once")
    prefix = "a path of the issuing server's source tree: "
    for spelled in cases(repository):
        for dash in ["-", "_", "--", "-_"]:
            for before in ["", "./", "../", "/", "~" + "/", "$HO" + "ME/", "work/", "see ", "`", "("]:
                for top in sorted(SERVER_FOLDERS):
                    for tail in ["x", "x/y.md", "mine.py"]:
                        name = spelled.replace("-", dash)
                        line = before + name + "/" + top + "/" + tail
                        lead = before if "/" in before and not before.startswith(".") else ""
                        if server_tree("x.md", line, own, {}, {}, repositories=repositories, folders=folders) != \
                                [(1, prefix + lead + name + "/" + top + "/" + tail)]:
                            found.append("the planted repository name was not found: %r" % line)
                        reference = top + "/" + tail
                        if server_tree("x.md", line, own, {}, {}) != ([] if reference in own else [(1, prefix + reference)]):
                            found.append("the check's own tables read a made-up repository name: %r" % line)
    for line in ["Example-Repository-Two/bi" + "n/x", "an-Example-Repository/bi" + "n/x", "ExampleRepository/bi" + "n/x"]:
        if server_tree("x.md", line, own, {}, {}, repositories=repositories, folders=folders) != [(1, prefix + "bi" + "n/x")]:
            found.append("a piece that is not the planted repository name was read as it: %r" % line)
    return found


def main():
    found = planted_problems() + problems()
    for line in found:
        print(line)
    print("check-stands-alone: %s" % ("OK" if not found else "%d problem(s)" % len(found)))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
