# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule RequisitionReceiptVerifier.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :requisition_receipt_verifier,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: false,
      deps: [],
      description:
        "Offline checker of Requisition authority receipts (Ed25519, registry key windows, log checkpoints): " <>
          "verify_receipt.exs, the Elixir twin of verify_receipt.py, as a library and a command. " <>
          "No dependency beyond Elixir and OTP; no network.",
      package: package(),
      escript: [main_module: RequisitionReceiptVerifier.CLI, name: "verify_receipt"],
      source_url: "https://github.com/ScriptKittyOS/HolyTrinity-Benchmark"
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
