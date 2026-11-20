# Where this package's code comes from

The package's three library files are derived mechanically, by `elixir/scripts/derive.exs`, from two scripts of the
Requisition receipt verifier. The scripts are kept unchanged in `elixir/sources/` and pinned by SHA-256 in
`elixir/test/package_test.exs`. These paths are in the Requisition Offline Verifier repository
(https://github.com/ScriptKittyOS/Requisition-Offline-Verifier); the Hex package does not carry them.

| script | SHA-256 |
|---|---|
| `elixir/sources/verify_receipt.exs` | `145e062865809dc88ab616629022e0579dbc32d04efc93c8700707dcf72d4800` |
| `elixir/sources/verify_receipt_checkpoint.exs` | `c575f8875d67eba418b4853db2f7cbd67a0dc79d1eda60f9920f7746e578e9b4` |

| package file | made from |
|---|---|
| `lib/verify_receipt.ex` | `verify_receipt.exs`, without its `#!` line and its last-resort block, its one `Code.require_file` line replaced by a comment, and its one top-level line (it loads the crypto application before the script's first module) replaced by a comment |
| `lib/log_checkpoint.ex` | `verify_receipt_checkpoint.exs`, without its `#!` line |
| `lib/requisition_receipt_verifier/cli.ex` | the line of `verify_receipt.exs` that loads the crypto application, then its last-resort block, as `RequisitionReceiptVerifier.CLI.main/1`, `System.argv()` replaced by its argument |

The third line of each of these files names its source script and the script's SHA-256.

The scripts' modules carry these names in the package. Every whole-word use of a script's module name becomes its
package name, in code and comments; no other text changes:

| script module | package module |
|---|---|
| `Ed25519Strict` | `RequisitionReceiptVerifier.Ed25519Strict` |
| `LogCheckpoint` | `RequisitionReceiptVerifier.LogCheckpoint` |
| `VerifyReceipt` | `RequisitionReceiptVerifier.VerifyReceipt` |

To check a copy, in the `elixir/` folder of that repository: `elixir scripts/derive.exs --write`, then
`git diff -- lib` shows no change; the tests do the same comparison (`mix test`).
