# requisition_receipt_verifier

`verify_receipt.exs`, the Elixir twin of the receipt verifier `verify_receipt.py`, as a Hex package. The receipt
verifiers are released in the `receipt-verification` folder of HolyTrinity-Benchmark; the Requisition Offline
Verifier and Requisition-Benchmark run `verify_receipt.py`. It checks
a Requisition authority receipt offline: the Ed25519 signature under a key registry the relying party supplies, the
key's status and signing window, and, when asked, the receipt's inclusion under a witnessed log checkpoint of
Requisition's evaluation environment (`CHECKPOINTS.md`). The exit codes and every verdict are defined in `VERDICTS.md`.

It needs Elixir and OTP (it uses OTP's `:json` module) and nothing else: no other package, no network. It was
tested with Elixir 1.18.4 and 1.19.2 on OTP 28.1.1, and Elixir 1.20.4 on OTP 29.1; other versions were not tested.

## Use

```elixir
# mix.exs
{:requisition_receipt_verifier, "== 0.1.0", runtime: false}
```

```sh
mix requisition_receipt_verifier.verify --receipt RECEIPT.json --registry REGISTRY.json
```

Or build the stand-alone command in this package's folder:

```sh
mix escript.build
./verify_receipt --receipt RECEIPT.json --registry REGISTRY.json
```

Both take the flags of `verify_receipt.exs` and give its output and exit code; both end the VM with that code.

## Where the code comes from

`lib/verify_receipt.ex`, `lib/log_checkpoint.ex` and `lib/requisition_receipt_verifier/cli.ex` are derived
mechanically from the scripts `verify_receipt.exs` and `verify_receipt_checkpoint.exs`; the first line after the
licence header of each names its source and the source's SHA-256. The derivation removes the scripts' `#!` lines,
moves the last-resort exception handler into `RequisitionReceiptVerifier.CLI.main/1`, replaces with a comment the one
line that loaded `verify_receipt_checkpoint.exs` from a file (the package compiles it), and puts the scripts' modules
under one
namespace (`SOURCES.md` gives the details and the sources' SHA-256):

| script module | package module |
|---|---|
| `Ed25519Strict` | `RequisitionReceiptVerifier.Ed25519Strict` |
| `LogCheckpoint` | `RequisitionReceiptVerifier.LogCheckpoint` |
| `VerifyReceipt` | `RequisitionReceiptVerifier.VerifyReceipt` |

## Licence

Apache License 2.0 (`LICENSE`, `NOTICE`). `LICENSE` here is the same text as the Requisition Offline
Verifier's `LICENSE`, byte for byte: the package must carry its own copy, because a Hex package holds the files inside
its own folder and no others.
