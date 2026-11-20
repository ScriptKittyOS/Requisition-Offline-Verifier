# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
# The crypto application is loaded here, when Mix reads this file, before Mix itself loads the crypto module on the
# way to a task of this project. On an Erlang build whose crypto module warns when it is loaded before its
# application, the runtime would otherwise write that warning to standard output ahead of the verdict of
# `mix requisition_receipt_verifier.verify` (the script and the command load it first for the same reason).
# Loading it starts nothing and reads no input.
:application.load(:crypto)

defmodule RequisitionReceiptVerifier.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :requisition_receipt_verifier,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: false,
      deps: [],
      description:
        "Offline checker of Requisition authority receipts (Ed25519, registry key windows, log checkpoints): " <>
          "verify_receipt.exs, the Elixir twin of verify_receipt.py, as a library and a command. " <>
          "No dependency beyond Elixir and OTP; no network.",
      package: package(),
      escript: [main_module: RequisitionReceiptVerifier.CLI, name: "verify_receipt"],
      source_url: "https://github.com/ScriptKittyOS/Requisition-Offline-Verifier"
    ]
  end

  def application, do: [extra_applications: [:crypto]]

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["Sudo Apt Holdings LLC (Script Kitty OS & Labs)"],
      links: %{
        "Requisition Offline Verifier" => "https://github.com/ScriptKittyOS/Requisition-Offline-Verifier",
        "Requisition-Benchmark" => "https://github.com/ScriptKittyOS/Requisition-Benchmark",
        "HolyTrinity-Benchmark" => "https://github.com/ScriptKittyOS/HolyTrinity-Benchmark"
      },
      files: ~w(lib mix.exs README.md SOURCES.md LICENSE NOTICE VERDICTS.md CHECKPOINTS.md)
    ]
  end
end
