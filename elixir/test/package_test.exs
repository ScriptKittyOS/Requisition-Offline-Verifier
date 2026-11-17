# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule RequisitionReceiptVerifier.PackageTest do
  # The package's library files are the verifier scripts' code, derived mechanically (scripts/derive.exs) from the
  # pinned sources; the package is Apache-2.0 and depends on nothing but OTP.
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  # verify_receipt.exs and verify_receipt_checkpoint.exs of requisition main 61e49fea (its verifier SHA256SUMS)
  @sources %{
    "sources/verify_receipt.exs" => "d8b618dc6fadd7557981fd62e7e3520708b741085ff9cc6c1569b8fb5f4fdbe0",
    "sources/verify_receipt_checkpoint.exs" => "b60a950096ba703050fa553577245703980d30f4c0fad97db918353af64aac28"
  }
  @apache "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
  @spdx "# SPDX-License-Identifier: Apache-2.0"
  @copyright "# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)"

  Code.require_file("../scripts/derive.exs", __DIR__)

  defp sha(path), do: :crypto.hash(:sha256, File.read!(Path.join(@root, path))) |> Base.encode16(case: :lower)

  # Each module of the scripts and its name in the package (README.md and SOURCES.md state it as a table row)
  @mapping %{
    "Ed25519Strict" => "RequisitionReceiptVerifier.Ed25519Strict",
    "LogCheckpoint" => "RequisitionReceiptVerifier.LogCheckpoint",
    "VerifyReceipt" => "RequisitionReceiptVerifier.VerifyReceipt"
  }

  test "every module of the package is under RequisitionReceiptVerifier (or its Mix task)" do
    {:ok, modules} = :application.get_key(:requisition_receipt_verifier, :modules)
    outside =
      for m <- modules, name = inspect(m),
          not String.starts_with?(name, ["RequisitionReceiptVerifier.", "Mix.Tasks.RequisitionReceiptVerifier."]),
          do: name
    assert outside == []
    assert Enum.sort(Enum.map(modules, &inspect/1)) ==
             Enum.sort(Map.values(@mapping) ++ ["RequisitionReceiptVerifier.CLI", "Mix.Tasks.RequisitionReceiptVerifier.Verify"])
  end

  test "the derivation renames exactly the scripts' three modules, and README.md and SOURCES.md state the mapping" do
    assert Derive.mapping() == @mapping
    for doc <- ["README.md", "SOURCES.md"], {script, package} <- @mapping do
      assert File.read!(Path.join(@root, doc)) =~ "| `#{script}` | `#{package}` |", "#{doc} lacks #{script}"
    end
  end

  test "the sources are the pinned scripts" do
    for {path, digest} <- @sources, do: assert(sha(path) == digest, path)
  end

  test "every library file the derivation makes is in lib/, byte for byte" do
    for {path, text} <- Derive.outputs(@root) do
      assert File.read!(Path.join(@root, path)) == text, "#{path} is not what scripts/derive.exs makes"
    end
  end

  test "lib/ holds the derived files and the Mix task, nothing else" do
    files = Path.wildcard(Path.join(@root, "lib/**/*.ex")) |> Enum.map(&Path.relative_to(&1, @root)) |> Enum.sort()
    assert files == Enum.sort(Map.keys(Derive.outputs(@root)) ++ ["lib/mix/tasks/requisition_receipt_verifier.verify.ex"])
  end

  test "every Elixir file of the package starts with the licence header" do
    for path <- ["mix.exs" | Path.wildcard(Path.join(@root, "lib/**/*.ex"))] do
      [first, second | _] = File.read!(Path.join(@root, Path.relative_to(path, @root))) |> String.split("\n")
      assert {first, second} == {@spdx, @copyright}, path
    end
  end

  test "Apache-2.0, the NOTICE, no dependency, and the files the package ships" do
    assert sha("LICENSE") == @apache
    assert "Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)" in String.split(File.read!(Path.join(@root, "NOTICE")), "\n")
    config = Mix.Project.config()
    assert config[:deps] == []
    assert config[:package][:licenses] == ["Apache-2.0"]
    assert config[:package][:files] == ~w(lib mix.exs README.md SOURCES.md LICENSE NOTICE VERDICTS.md CHECKPOINTS.md)
    assert config[:escript][:main_module] == RequisitionReceiptVerifier.CLI
  end
end
