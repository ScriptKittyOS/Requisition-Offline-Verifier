# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# Derived by scripts/derive.exs from verify_receipt.exs, sha256 d8b618dc6fadd7557981fd62e7e3520708b741085ff9cc6c1569b8fb5f4fdbe0.
defmodule RequisitionReceiptVerifier.CLI do
  @moduledoc "The command line of verify_receipt.exs, as an escript and a Mix task: the same flags, output and exits."

  def main(argv) do
    # Last resort, for an exception no check above foresaw. Exit 2 ("nothing was measured"), because
    # neither 0 nor 1 may be said of an input this file could not evaluate, and no stack trace: the
    # type of the exception is named so the defect can be reported.
    try do
      RequisitionReceiptVerifier.VerifyReceipt.main(argv)
    rescue
      error ->
        IO.puts(
          :stderr,
          "internal error (#{inspect(error.__struct__)}): this verifier could not evaluate the input; nothing was measured."
        )

        System.halt(2)
    catch
      kind, _reason ->
        IO.puts(
          :stderr,
          "internal error (#{kind}): this verifier could not evaluate the input; nothing was measured."
        )

        System.halt(2)
    end
  end
end
