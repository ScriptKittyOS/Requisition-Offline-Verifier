# Where this package's code comes from

The package's three library files are derived mechanically, by `scripts/derive.exs`, from two scripts of the
Requisition receipt verifier. The scripts are kept unchanged in `sources/` and pinned by SHA-256 in
`test/package_test.exs`:

| script | SHA-256 |
|---|---|
| `sources/verify_receipt.exs` | `d8b618dc6fadd7557981fd62e7e3520708b741085ff9cc6c1569b8fb5f4fdbe0` |
| `sources/verify_receipt_checkpoint.exs` | `b60a950096ba703050fa553577245703980d30f4c0fad97db918353af64aac28` |

| package file | made from |
|---|---|
| `lib/verify_receipt.ex` | `verify_receipt.exs`, without its `#!` line and its last-resort block, its one `Code.require_file` line replaced by a comment |
| `lib/log_checkpoint.ex` | `verify_receipt_checkpoint.exs`, without its `#!` line |
| `lib/requisition_receipt_verifier/cli.ex` | the last-resort block of `verify_receipt.exs`, as `RequisitionReceiptVerifier.CLI.main/1`, `System.argv()` replaced by its argument |

The third line of each of these files names its source script and the script's SHA-256.

The scripts' modules carry these names in the package. Every whole-word use of a script's module name becomes its
package name, in code and comments; no other text changes:

| script module | package module |
|---|---|
| `Ed25519Strict` | `RequisitionReceiptVerifier.Ed25519Strict` |
| `LogCheckpoint` | `RequisitionReceiptVerifier.LogCheckpoint` |
| `VerifyReceipt` | `RequisitionReceiptVerifier.VerifyReceipt` |

To check a copy: `elixir scripts/derive.exs --write` in this folder, then `git diff -- lib` shows no change; the tests
do the same comparison (`mix test`).
