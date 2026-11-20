# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
defmodule RequisitionReceiptVerifier.PassLinesTest do
  # What a pass says, through the package's command (RequisitionReceiptVerifier.CLI.main/1, what the escript and the
  # Mix task run), in a child VM because a verdict ends the VM with its exit code.
  #
  #   * every pass prints one fixed sentence after its verdict: the bytes were signed under the key supplied, and it is
  #     not permission to act. A failure does not print it;
  #   * a deadline the signed bytes carry is reported as what the record says, for a decision that allowed (the signed
  #     verdict is "allow") and for a statement (no signed verdict, and exp), each in its own words, and for no other
  #     record: a caller grant signs not_after and no verdict, and is not reported as a decision. It is compared with
  #     nothing unless a time is given (--at); no exit depends on the time;
  #   * the first line of a pass is the command's own: the runtime writes no line before it;
  #   * a time that is not one instant of the accepted form is a usage error (exit 2);
  #   * the same valid decision record presented twice gives the same pass, the same lines and the same exit: replay
  #     protection is not the verifier's.
  #
  # The rows are test/pass_lines_vectors.v1.json, one file for every Requisition verifier (VERDICTS.md, "What a pass
  # says", states them as a table). Each row names a kind of record and the members its signed metadata carries; the
  # record is built and signed here with an Ed25519 key made for the run, because the rows include shapes no issuing
  # system signs (a deadline that is no instant, a start after the end).
  use ExUnit.Case, async: true

  @doc_ Path.join(__DIR__, "pass_lines_vectors.v1.json") |> File.read!() |> :json.decode()
  @pass_line @doc_["pass_line"]
  @vectors @doc_["vectors"]
  @malformed @doc_["malformed_at"]
  @unknown Enum.map(@doc_["unknown_arguments"], & &1["argv"])
  @kid "requisition_lab_dev_ed25519_v0"

  defp json(term), do: term |> :json.encode() |> IO.iodata_to_binary()
  defp null_to_nil(:null), do: nil
  defp null_to_nil(value), do: value

  defp receipt_type("statement"), do: "requisition.lab.statement.v0"
  defp receipt_type("grant"), do: "requisition.lab.caller_grant.v0"
  defp receipt_type(_decision_or_cease), do: "requisition.lab.decision.v0"

  defp signed_text(kind, members) do
    json(%{
      "schema_version" => "agent_receipt.v1",
      "chain_scope" => "requisition-lab:account:00000000-0000-4000-8000-000000000001",
      "sequence" => 1,
      "previous_hash" => :null,
      "receipt_type" => receipt_type(kind),
      "subject_type" => "requisition.lab.pass_lines",
      "subject_id" => "pass-lines",
      "status" => "recorded",
      "payload_hash" => :null,
      "occurred_at" => "2026-11-13T15:56:48Z",
      "metadata" => Map.merge(%{"profile" => "lab", "signer" => "dev", "key_id" => @kid}, members)
    })
  end

  defp envelope(text, signature) do
    json(%{
      "signature" => Base.encode64(signature),
      "key_id" => @kid,
      "signed_payload" => text,
      "receipt_hash" => Base.encode16(:crypto.hash(:sha256, text), case: :lower)
    })
  end

  defp run(record, keys, flags) do
    {output, status} =
      System.cmd(
        "elixir",
        ["-pa", Mix.Project.compile_path(), "-e", "RequisitionReceiptVerifier.CLI.main(System.argv())", "--",
         "--receipt", record, "--registry", keys] ++ flags,
        stderr_to_stdout: true
      )

    {status, output}
  end

  # The lines after the fixed sentence, blank lines left out; :no_pass_line when it is not printed.
  defp said(output) do
    lines = output |> String.split("\n") |> Enum.map(&String.trim_trailing/1) |> Enum.reject(&(&1 == ""))

    case Enum.count(lines, &(&1 == @pass_line)) do
      0 -> :no_pass_line
      1 -> {:pass, lines |> Enum.drop_while(&(&1 != @pass_line)) |> tl()}
      n -> {:pass_line_times, n}
    end
  end

  setup_all do
    dir = Path.join(Mix.Project.build_path(), "pass-lines-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
    sign = fn text -> :crypto.sign(:eddsa, :none, text, [secret, :ed25519]) end
    keys = Path.join(dir, "keys.json")

    File.write!(
      keys,
      json(%{
        "entries" => [
          %{
            "key_id" => @kid,
            "algorithm" => "ed25519",
            "status" => "active",
            "status_changed_at" => "2026-01-01T00:00:00Z",
            "valid_from" => "2026-01-01T00:00:00Z",
            "valid_to" => :null,
            "public_key" => Base.encode64(public),
            "public_key_fingerprint" => Base.encode16(:crypto.hash(:sha256, public), case: :lower)
          }
        ]
      })
    )

    write = fn name, body ->
      path = Path.join(dir, name <> ".json")
      File.write!(path, body)
      path
    end

    records =
      Map.new(@vectors, fn vector ->
        text = signed_text(vector["kind"], vector["metadata"])
        {vector["name"], write.(vector["name"], envelope(text, sign.(text)))}
      end)

    allow = Enum.find(@vectors, &(&1["name"] == "allow_no_time"))
    text = signed_text("decision", allow["metadata"])
    changed = String.replace(text, ~s("verdict":"allow"), ~s("verdict":"alloW"))
    true = changed != text
    tampered = write.("tampered", envelope(changed, sign.(text)))

    jobs =
      for(v <- @vectors, do: {{:vector, v["name"]}, {records[v["name"]], at_flags(null_to_nil(v["at"]))}}) ++
        for(at <- @malformed, do: {{:malformed, at}, {records["allow_no_time"], ["--at", at]}}) ++
        [{:dangling, {records["allow_no_time"], ["--at"]}}] ++
        for(argv <- @unknown, do: {{:unknown, argv}, {records["allow_no_time"], argv}}) ++
        for(flags <- [[], ["--at", "2026-11-13T15:57:00Z"]], do: {{:tampered, flags}, {tampered, flags}}) ++
        for(n <- [1, 2], do: {{:replay, n}, {records["allow_no_time"], []}})

    runs =
      jobs
      |> Task.async_stream(fn {id, {record, flags}} -> {id, run(record, keys, flags)} end, max_concurrency: 4, timeout: 55_000)
      |> Map.new(fn {:ok, pair} -> pair end)

    %{runs: runs}
  end

  defp at_flags(nil), do: []
  defp at_flags(at), do: ["--at", at]

  test "every row passes with exit 0, ends with the fixed sentence and then exactly the row's lines", %{runs: runs} do
    wrong =
      for vector <- @vectors,
          {status, output} = runs[{:vector, vector["name"]}],
          {status, said(output)} != {0, {:pass, vector["lines"]}},
          do: "#{vector["name"]}: exit #{status}, #{inspect(said(output))}\n  expected #{inspect(vector["lines"])}\n#{output}"

    assert wrong == [], Enum.join(wrong, "\n")
  end

  test "a time that is not one instant of the accepted form is a usage error, and nothing passes", %{runs: runs} do
    for at <- @malformed do
      {status, output} = runs[{:malformed, at}]
      assert {status, said(output)} == {2, :no_pass_line}, "--at #{inspect(at)}: exit #{status}\n#{output}"
    end

    {status, output} = runs[:dangling]
    assert {status, said(output)} == {2, :no_pass_line}, "--at with no value: exit #{status}\n#{output}"
  end

  test "an argument the command does not take is a usage error, and nothing passes: none is skipped in silence", %{runs: runs} do
    assert length(@unknown) >= 5

    for argv <- @unknown do
      {status, output} = runs[{:unknown, argv}]
      assert {status, said(output)} == {2, :no_pass_line}, "#{inspect(argv)}: exit #{status}\n#{output}"
      refute output =~ "VERIFIED", output
    end
  end

  test "a record whose signature fails prints no fixed sentence and no window line, with or without a time", %{runs: runs} do
    for flags <- [[], ["--at", "2026-11-13T15:57:00Z"]] do
      {status, output} = runs[{:tampered, flags}]
      assert status == 1, "#{inspect(flags)}: exit #{status}\n#{output}"
      assert said(output) == :no_pass_line, output
      refute output =~ "allowed execution until", output
      refute output =~ "was valid until", output
      refute output =~ "No time was compared", output
      refute output =~ "the window was", output
    end
  end

  test "replay protection is not the verifier's: the same valid decision record presented twice gives the same pass, the same lines and the same exit code",
       %{runs: runs} do
    {first_status, first} = runs[{:replay, 1}]
    assert first_status == 0
    {second_status, second} = runs[{:replay, 2}]
    assert {second_status, second} == {first_status, first}
    assert {:pass, ["This decision allowed execution until 2026-11-13T15:57:48Z.", "No time was compared."]} = said(first)
  end

  test "only a signed verdict of allow is reported as a decision, only a record with no verdict and with exp as a statement, in the rows and in every run",
       %{runs: runs} do
    wrong =
      for vector <- @vectors,
          {_status, output} = runs[{:vector, vector["name"]}],
          text <- [Enum.join(vector["lines"], "\n"), output],
          (vector["metadata"]["verdict"] != "allow" and text =~ "This decision") or
            ((Map.has_key?(vector["metadata"], "verdict") or not Map.has_key?(vector["metadata"], "exp")) and text =~ "This statement"),
          do: "#{vector["name"]}: #{text}"

    assert wrong == [], Enum.join(wrong, "\n")
    # a record shaped as a caller grant (not_after, no verdict), with and without a time
    for name <- ~w(grant_no_time grant_at) do
      vector = Enum.find(@vectors, &(&1["name"] == name))
      assert vector["kind"] == "grant" and Map.keys(vector["metadata"]) == ["not_after"], name
    end
  end

  test "the first line of every pass is the command's own: the runtime writes no line before it, and none anywhere", %{runs: runs} do
    wrong =
      for vector <- @vectors,
          {_status, output} = runs[{:vector, vector["name"]}],
          not String.starts_with?(output, "VERIFIED — signature is valid under key_id ") or output =~ "[warning]" or
            output =~ "loaded without application",
          do: "#{vector["name"]}: #{inspect(String.slice(output, 0, 200))}"

    assert wrong == [], Enum.join(wrong, "\n")
  end

  test "the command loads the crypto application before anything else, and the script it is made from does so before its first module" do
    cli = File.read!(Path.expand("../lib/requisition_receipt_verifier/cli.ex", __DIR__))
    [_head, body] = String.split(cli, "  def main(argv) do\n", parts: 2)
    assert String.starts_with?(body, "    :application.load(:crypto)\n")
    [head, _modules] = File.read!(Path.expand("../sources/verify_receipt.exs", __DIR__)) |> String.split("\ndefmodule ", parts: 2)
    assert ":application.load(:crypto)" in String.split(head, "\n")
    refute ":application.load(:crypto)" in String.split(File.read!(Path.expand("../lib/verify_receipt.ex", __DIR__)), "\n")
  end

  test "the exit of a pass does not depend on the time given: open, closed and not compared exit alike", %{runs: runs} do
    exits =
      for name <- ~w(allow_no_time allow_before_start allow_at_start allow_at_end allow_after_end end_not_a_day_at),
          do: elem(runs[{:vector, name}], 0)

    assert Enum.uniq(exits) == [0], inspect(exits)
  end

  test "the vector file is the one VERDICTS.md states, row for row, and the package's fixed sentence is the file's" do
    text = File.read!(Path.expand("../VERDICTS.md", __DIR__))
    assert text =~ "\n> " <> @pass_line <> "\n"

    for vector <- @vectors do
      at = if vector["at"] == :null, do: "none", else: "`#{vector["at"]}`"
      lines = if vector["lines"] == [], do: "none", else: Enum.join(vector["lines"], "<br>")
      assert text =~ "| `#{vector["name"]}` | #{vector["kind"]} | `", vector["name"]
      assert text =~ "` | #{at} | #{lines} |\n", vector["name"]
    end

    assert File.read!(Path.expand("../lib/verify_receipt.ex", __DIR__)) =~ ~s(  @pass_line ") <> @pass_line <> ~s("\n)
  end
end
