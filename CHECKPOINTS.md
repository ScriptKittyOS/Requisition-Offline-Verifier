# `bin/verify_offline.py` and log checkpoints

`bin/verify_offline.py` checks one lab record of the evaluation environment: that it binds the arguments shown, its
Ed25519 signature (through Requisition's `bin/lab-verify`) and its post-quantum signature or co-signature, as the
evaluation environment makes them. With the flags below it also checks what the transparency log of the evaluation
environment says of the record. The log, its checkpoints and its witnesses exist in the evaluation environment only.

    # a record of the evaluation environment, checked against its log
    python3 -I bin/verify_offline.py --arguments ARGS.json --act-type NAME --record RECORD.json \
        --lab-verify /path/to/bin/lab-verify --registry LAB-KEYS.json \
        --checkpoint NOTE --inclusion-proof PROOF.json --witness-policy POLICY \
        [--held-size N --held-root ROOT | --held-state FILE [--write-held-state]] \
        [--consistency-proof PROOF.json] [--key-transition RECORD.json]

The flags are handed, as given, to `bin/lab-verify`, which hands them to Requisition's receipt verifier
`verify_receipt.py`. That file does the checks. Its `CHECKPOINTS.md` (beside it, in
`bench/holytrinity-v2/verifier/`) states each check, each input, every refusal code, the adversary model and what is
not checked. In short:

1. in the evaluation environment, the record's leaf is included, by an RFC 9162 inclusion proof, under a checkpoint
   that the log key your policy names signed and that the witnesses it names cosigned, meeting its quorum;
2. a checkpoint larger than the tree size you hold is consistent with your tree (an RFC 9162 consistency proof);
3. a checkpoint smaller than the tree size you hold, or of that size with another root, is refused.

A pass shows that the record is in the log's tree at the checkpoint's size, and that this tree is an append-only
extension of the tree you hold. It does not show that the checkpoint is the log's newest, nor that the act ran, or
ran once. A log can show different histories to different parties. A consistency proof covers only the two trees it
connects; in the evaluation environment, cosignatures from witness keys you configure, at your threshold, are what
make such a fork detectable.

What this file adds:

- the co-signature beside the record (in RECORD.json or `--cosignature`) is handed on with it, because its bytes
  are part of the record's leaf in the log;
- a checkpoint refusal ends `verdict: FAIL (the log checkpoint: <verdict_code>)`, exit 6;
- an error in the inputs you give for the evaluation environment's log (a held size without its root, a policy with no
  log line, an unreadable held-state file) is a usage error, exit 2, as in `bin/lab-verify` and `verify_receipt.py`;
- a pass needs `bin/lab-verify`'s line `log checkpoint: all checks held: ...`, else it FAILS with exit 6 too, and
  section 4 of the output prints the `log checkpoint:` lines;
- the PASS line then adds: "It is included in a checkpoint of the evaluation environment's log that the log key and
  the witnesses of the given policy signed, not older than the tree size given".

The held-state file (`--held-state`, written only with `--write-held-state`, after a full pass) is yours. It resists a
rollback only as far as the file itself does: lost or reset, the next checkpoint is compared with nothing; restored
from a backup, copied from an older machine or written by someone else, it is compared with that state. The file
carries no signature or checksum of its own.

Not checked here, in the evaluation environment: a record whose own signature is ML-DSA-87 (`bin/lab-verify` refuses
the flags on that path, `lab_checkpoint_unchecked_mldsa87`, and this file then FAILS with exit 3), and ML-DSA-44
witness cosignatures (`checkpoint_algorithm_unsupported`). `bin/verify_chain.py` takes no checkpoint: the log is one
tree over every chain, so a row's inclusion under a checkpoint does not show that an export holds its chain's last row.
