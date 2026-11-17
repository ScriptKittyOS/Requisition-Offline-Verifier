# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
#
# Derives the package's two library files from the verifier's scripts in sources/, mechanically, so that what the
# package compiles is the scripts' code and nothing else:
#
#   lib/verify_receipt.ex   = sources/verify_receipt.exs without its "#!" line, without the script's last-resort
#                             block (from the line "# Last resort, ..." to the end; RequisitionReceiptVerifier.CLI
#                             carries that block), and with its one Code.require_file line replaced by a comment
#                             (LogCheckpoint is compiled with the package, so there is nothing to load)
#   lib/log_checkpoint.ex   = sources/verify_receipt_checkpoint.exs without its "#!" line
#   lib/requisition_receipt_verifier/cli.ex
#                           = RequisitionReceiptVerifier.CLI.main/1: the script's last-resort block, its comment and
#                             code, indented into the function, with System.argv() replaced by the argument argv
#
# In all three, each of the scripts' module names (mapping/0), as a whole word not preceded by a dot, becomes its name
# under RequisitionReceiptVerifier, comments included; no string literal of the scripts holds one of these names.
# Each file starts with a line naming its source and the source's SHA-256.
#   elixir scripts/derive.exs --write     writes them; without --write it only defines Derive (for the tests)
defmodule Derive do
  @require ~s|          Code.require_file("verify_receipt_checkpoint.exs", __DIR__)\n|
  @packaged "          # (packaged: LogCheckpoint is compiled with this module; nothing is loaded here)\n"
  @last_resort "# Last resort, for an exception no check above foresaw."

  @mapping %{
    "Ed25519Strict" => "RequisitionReceiptVerifier.Ed25519Strict",
    "LogCheckpoint" => "RequisitionReceiptVerifier.LogCheckpoint",
    "VerifyReceipt" => "RequisitionReceiptVerifier.VerifyReceipt"
  }

  def mapping, do: @mapping

  def outputs(root) do
    receipt = File.read!(Path.join(root, "sources/verify_receipt.exs"))
    checkpoint = File.read!(Path.join(root, "sources/verify_receipt_checkpoint.exs"))
    %{
      "lib/verify_receipt.ex" => from(receipt, "verify_receipt.exs", &receipt_body/1),
      "lib/log_checkpoint.ex" => from(checkpoint, "verify_receipt_checkpoint.exs", & &1),
      "lib/requisition_receipt_verifier/cli.ex" => from(receipt, "verify_receipt.exs", &cli/1)
    }
  end

  defp from(text, name, transform) do
    "#!/usr/bin/env elixir\n" <> rest = text
    sha = :crypto.hash(:sha256, text) |> Base.encode16(case: :lower)
    # the source's own SPDX and copyright lines come first, then the derivation line
    [spdx, copyright, rest2] = String.split(rest, "\n", parts: 3)
    Enum.join([spdx, copyright, "# Derived by scripts/derive.exs from #{name}, sha256 #{sha}.", rename(transform.(rest2))], "\n")
  end

  defp receipt_body(text) do
    1 = count(text, @require)
    [body, _block] = String.split(text, @last_resort, parts: 2)
    1 = count(text, @last_resort)
    String.replace(body, @require, @packaged) |> String.trim_trailing() |> Kernel.<>("\n")
  end

  defp cli(text) do
    [_body, block] = String.split(text, @last_resort, parts: 2)
    call = "VerifyReceipt.main(System.argv())"
    1 = count(block, call)
    block = String.replace(@last_resort <> block, call, "VerifyReceipt.main(argv)")
    indented = block |> String.trim_trailing() |> String.split("\n") |> Enum.map_join("\n", &indent/1)

    """
    defmodule RequisitionReceiptVerifier.CLI do
      @moduledoc "The command line of verify_receipt.exs, as an escript and a Mix task: the same flags, output and exits."

      def main(argv) do
    #{indented}
      end
    end
    """
  end

  defp indent(""), do: ""
  defp indent(line), do: "    " <> line

  defp rename(text) do
    Regex.replace(~r/(?<![.\w])(Ed25519Strict|LogCheckpoint|VerifyReceipt)\b/, text, fn _, name -> @mapping[name] end)
  end

  defp count(text, part), do: length(String.split(text, part)) - 1

  def write!(root) do
    for {path, text} <- outputs(root), do: File.write!(Path.join(root, path), text)
  end
end

if "--write" in System.argv(), do: Derive.write!(Path.expand("..", __DIR__))
