#!/usr/bin/env escript
%% Erlang/OTP :crypto (OpenSSL) over a cases file. usage: escript verify.escript CASES.tsv
%% OTP's :crypto takes no ML-DSA context argument, so only the cases with the EMPTY context are run; the others
%% are counted as not run. Exit 0 when no case that ran disagrees with its expected result, 1 when any does,
%% 3 when this Erlang/OpenSSL has no ML-DSA-87.
main([Cases]) ->
    {ok, _} = application:ensure_all_started(crypto),
    case lists:member(mldsa87, proplists:get_value(public_keys, crypto:supports(), [])) of
        true -> run(Cases);
        false -> io:format(standard_error, "this Erlang/OTP :crypto has no mldsa87 (OpenSSL ~s)~n", [element(3, hd(crypto:info_lib()))]), halt(3)
    end;
main(_) ->
    halt(2).

run(Cases) ->
    {ok, Bin} = file:read_file(Cases),
    All = [binary:split(L, <<"\t">>, [global]) || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    Run = [C || [_, _, _, _, <<"-">>, _] = C <- All],
    B = fun(<<"-">>) -> <<>>; (H) -> binary:decode_hex(H) end,
    V = fun(Pk, Sig, Msg) -> try crypto:verify(mldsa87, none, Msg, Sig, Pk) of R -> R =:= true catch _:_ -> false end end,
    Wrong = [Id || [Id, Pk, Sig, Msg, _, E] <- Run, V(B(Pk), B(Sig), B(Msg)) =/= (E =:= <<"1">>)],
    Ids = "[" ++ lists:join(",", [binary_to_list(I) || I <- Wrong]) ++ "]",
    [{_, _, Ver}] = crypto:info_lib(),
    io:format("Erlang/OTP ~s :crypto on ~s: ~p cases with the empty context, ~p disagree with the expected result ~s; ~p cases with a context not run (no context argument)~n",
              [erlang:system_info(otp_release), Ver, length(Run), length(Wrong), Ids, length(All) - length(Run)]),
    halt(case Wrong of [] -> 0; _ -> 1 end).
