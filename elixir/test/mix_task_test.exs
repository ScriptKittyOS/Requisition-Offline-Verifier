# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule RequisitionReceiptVerifier.MixTaskTest do
  # The Mix task has the output of the script: its standard output begins with the verdict, on every runtime, as the
  # script's and the command's do. A runtime whose crypto module warns when it is loaded before its application would
  # otherwise write that warning first.
  use ExUnit.Case, async: false

  @root Path.expand("..", __DIR__)
  @vectors Path.expand("../../checkpoint-vectors", __DIR__)

  test "the task's standard output begins with the verdict" do
    # A fresh clone has no build: Mix would write its compiling lines first. The build is made here, so the run below
    # writes only what the task writes.
    {_, 0} = System.cmd("mix", ["compile"], cd: @root, stderr_to_stdout: true)

    {out, rc} =
      System.cmd(
        "mix",
        ["requisition_receipt_verifier.verify", "--receipt", Path.join(@vectors, "records/main-1.json")] ++
          ["--registry", Path.join(@vectors, "lab-keys.json")],
        cd: @root
      )

    assert rc == 0, out
    assert String.starts_with?(out, "VERIFIED"), "the task's standard output begins with: " <> String.slice(out, 0, 200)
  end
end
