# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule RequisitionReceiptVerifier.CheckpointInputsTest do
  # The inputs of the evaluation environment's log checkpoint check, in another form, through the package's command
  # (RequisitionReceiptVerifier.CLI.main/1, in a child VM because a verdict ends the VM with its exit code), over four
  # passing cases of ../checkpoint-vectors/ (the same inputs as checkpoint-test.sh, which runs verify_offline.py):
  #
  #   * a file given to a JSON flag of the check is given whatever JSON value it holds: false, true, null, 0, 1, "",
  #     "x", [] and {} are each a proof or a key-transition record of the wrong form, refused by its code (exit 5), and
  #     for the held-state file a usage error (exit 2); never the flag left out;
  #   * a member written as any bare JSON value (null, false, true, 0, "", [], {}) is present: a proof's hash is absent
  #     or "sha256", its leaf_hash, where written, the record's leaf hash, and the record's cosignature, where written,
  #     a text or an object whose member signature is that text; each is refused by its code, except the empty text as
  #     the cosignature, a co-signature of no bytes; a member left out is absent (a pass, or for the signature of a
  #     cosignature object, an object of the wrong form).
  use ExUnit.Case, async: true

  @vectors Path.expand("../../checkpoint-vectors", __DIR__)
  @manifest @vectors |> Path.join("manifest.json") |> File.read!() |> :json.decode()

  defp v(rel), do: Path.join(@vectors, rel)
  defp kase(name), do: Enum.find(@manifest["cases"], &(&1["name"] == name))

  defp args(k) do
    held =
      case k["held"] do
        %{"size" => size, "root" => root} -> ["--held-size", Integer.to_string(size), "--held-root", root]
        _none -> []
      end

    optional =
      for {member, flag} <- [
            {"consistency_proof", "--consistency-proof"},
            {"key_transition", "--key-transition"},
            {"held_to_transition_proof", "--held-to-transition-proof"}
          ],
          is_binary(k[member]),
          arg <- [flag, v(k[member])],
          do: arg

    ["--checkpoint", v(k["checkpoint"]), "--inclusion-proof", v(k["inclusion_proof"])] ++
      ["--witness-policy", v(k["witness_policy"])] ++ held ++ optional
  end

  defp put_flag(args, flag, value) do
    case Enum.find_index(args, &(&1 == flag)) do
      nil -> args ++ [flag, value]
      i -> List.replace_at(args, i + 1, value)
    end
  end

  defp drop_flag(args, flag) do
    case Enum.find_index(args, &(&1 == flag)) do
      nil -> args
      i -> args |> List.delete_at(i + 1) |> List.delete_at(i)
    end
  end

  defp run(record, flags) do
    System.cmd(
      "elixir",
      ["-pa", Mix.Project.compile_path(), "-e", "RequisitionReceiptVerifier.CLI.main(System.argv())", "--",
       "--receipt", record, "--registry", v(@manifest["registry"])] ++ flags,
      stderr_to_stdout: true
    )
  end

  defp code(out) do
    case Regex.scan(~r/verdict_code: ([a-z_0-9]+)/, out) do
      [] -> nil
      found -> found |> List.last() |> List.last()
    end
  end

  defp answered?(:usage, _out, rc), do: rc == 2
  defp answered?(:pass, out, rc), do: rc == 0 and out =~ "log checkpoint: all checks held"
  defp answered?(want, out, rc), do: rc == 5 and code(out) == want

  defp misses(runs) do
    runs
    |> Task.async_stream(fn {label, record, flags, want} -> {label, want, run(record, flags)} end,
      timeout: 240_000,
      max_concurrency: 4
    )
    |> Enum.flat_map(fn {:ok, {label, want, {out, rc}}} ->
      if answered?(want, out, rc), do: [], else: ["#{label}: exit #{rc}, #{inspect(code(out))}; expected #{inspect(want)}"]
    end)
  end

  @bare ["false", "true", "null", "0", "1", "\"\"", "\"x\"", "[]", "{}"]

  # the files a test writes go in a folder of its own under the system's temporary folder, removed at its end
  setup do
    dir = Path.join(System.tmp_dir!(), "checkpoint-inputs-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, dir: dir}
  end

  @tag timeout: 600_000
  test "a file given to a JSON flag of the check is given whatever it holds, and is refused as a file of the wrong form",
       %{dir: dir} do
    contexts = [
      {"--inclusion-proof", "included-no-held", & &1, "checkpoint_proof_malformed"},
      {"--consistency-proof", "consistent-with-held", & &1, "checkpoint_proof_malformed"},
      {"--key-transition", "key-transition-followed", & &1, "checkpoint_transition_unendorsed"},
      {"--key-transition", "included-no-held", & &1, "checkpoint_transition_unendorsed"},
      {"--held-to-transition-proof", "transition-held-older-both-proofs", & &1, "checkpoint_proof_malformed"},
      {"--held-state", "consistent-with-held", &(&1 |> drop_flag("--held-size") |> drop_flag("--held-root")), :usage}
    ]

    runs =
      for {flag, name, shape, want} <- contexts, {value, n} <- Enum.with_index(@bare) do
        path = Path.join(dir, "#{String.trim_leading(flag, "-")}-#{name}-#{n}.json")
        File.write!(path, value <> "\n")
        k = kase(name)
        {"#{flag} holding #{value} (#{name})", v(k["record"]), k |> args() |> shape.() |> put_flag(flag, path), want}
      end

    assert length(runs) == 54
    assert misses(runs) == []
  end

  @tag timeout: 600_000
  test "a member written as any bare JSON value is present, and judged as the check says; a member left out is absent",
       %{dir: dir} do
    edit = fn rel, fun, name ->
      path = Path.join(dir, name)
      document = rel |> v() |> File.read!() |> :json.decode() |> fun.()
      File.write!(path, :json.encode(document))
      path
    end

    # each member a checkpoint input may leave out, written as each bare JSON value, and left out; the empty text as the
    # cosignature (or as its object's signature) is a co-signature of no bytes, the same leaf as none: a pass
    members = [
      {"inclusion_proof", "hash", "included-no-held", "checkpoint_proof_malformed"},
      {"inclusion_proof", "leaf_hash", "included-no-held", "checkpoint_inclusion_invalid"},
      {"consistency_proof", "hash", "consistent-with-held", "checkpoint_proof_malformed"},
      {"held_to_transition_proof", "hash", "transition-held-older-both-proofs", "checkpoint_proof_malformed"},
      {"record", "cosignature", "included-no-held", "checkpoint_leaf_malformed"},
      {"record", "cosignature.signature", "included-no-held", "checkpoint_leaf_malformed"}
    ]

    forms =
      for {file, member, name, refusal} <- members, value <- [:null, false, true, 0, "", [], %{}, :left_out] do
        passes = (value == :left_out and member != "cosignature.signature") or (file == "record" and value == "")
        {file, member, value, name, if(passes, do: :pass, else: refusal)}
      end

    assert length(forms) == 48

    runs =
      for {{file, member, value, name, want}, n} <- Enum.with_index(forms) do
        k = kase(name)
        fun =
          cond do
            member == "cosignature.signature" and value == :left_out -> &Map.put(&1, "cosignature", %{})
            member == "cosignature.signature" -> &Map.put(&1, "cosignature", %{"signature" => value})
            value == :left_out -> &Map.delete(&1, member)
            true -> &Map.put(&1, member, value)
          end
        path = edit.(k[file], fun, "#{file}-#{n}.json")
        label = "#{member} of #{file} #{inspect(value)} (#{name})"

        if file == "record",
          do: {label, path, args(k), want},
          else: {label, v(k["record"]), put_flag(args(k), "--" <> String.replace(file, "_", "-"), path), want}
      end

    assert misses(runs) == []
  end
end
