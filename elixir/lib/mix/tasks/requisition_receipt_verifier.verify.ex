# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule Mix.Tasks.RequisitionReceiptVerifier.Verify do
  @shortdoc "Checks a Requisition authority receipt offline (the flags and exits of verify_receipt.exs)"
  @moduledoc """
  mix requisition_receipt_verifier.verify --receipt RECEIPT.json --registry REGISTRY.json [--at TIME] [checkpoint flags]

  The same flags, output and exit codes as verify_receipt.exs (VERDICTS.md, CHECKPOINTS.md). It ends the VM with
  the verdict's exit code.
  """
  use Mix.Task

  @impl Mix.Task
  def run(argv), do: RequisitionReceiptVerifier.CLI.main(argv)
end
