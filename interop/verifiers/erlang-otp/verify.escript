#!/usr/bin/env escript
%% Erlang/OTP :crypto (OpenSSL) over a cases file. usage: escript verify.escript CASES.tsv
%% OTP's :crypto takes no ML-DSA context argument, so only the cases with the EMPTY context are run; the others
%% are counted as not run. Exit 0 when no case that ran disagrees with its expected result, 1 when any does,
%% 2 on bad input (a bad command line, an unreadable file, a malformed line, no case run),
%% 3 when this Erlang/OpenSSL has no ML-DSA-87.
main([Cases]) ->
    {ok, _} = application:ensure_all_started(crypto),
    case lists:member(mldsa87, proplists:get_value(public_keys, crypto:supports(), [])) of
        true -> run(Cases);
        false -> io:format(standard_error, "this Erlang/OTP :crypto has no mldsa87 (~s)~n", [element(3, hd(crypto:info_lib()))]), halt(3)
    end;
main(_) ->
    io:format(standard_error, "usage: verify.escript CASES.tsv~n", []),
    halt(2).

run(Cases) ->
    Bin = case file:read_file(Cases) of
              {ok, B0} -> B0;
              {error, _} -> io:format(standard_error, "cannot read ~s~n", [Cases]), halt(2)
          end,
    All = [binary:split(L, <<"\t">>, [global]) || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    Bad = fun(Msg) -> io:format(standard_error, "~s~n", [Msg]), halt(2) end,
    IsHex = fun(<<"-">>) -> true; (H) -> H =/= <<>> andalso byte_size(H) rem 2 =:= 0 andalso lists:all(fun(C) -> (C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse (C >= $A andalso C =< $F) end, binary_to_list(H)) end,
    lists:foreach(fun([_, Pk0, Sig0, Msg0, Ctx0, E0]) -> case lists:all(IsHex, [Pk0, Sig0, Msg0, Ctx0]) andalso (E0 =:= <<"0">> orelse E0 =:= <<"1">>) of true -> ok; false -> Bad("bad hex or expected result") end;
                     (_) -> Bad("bad line") end, All),
    case All of [] -> Bad("no cases"); _ -> ok end,
    Run = [C || [_, _, _, _, <<"-">>, _] = C <- All],
    case Run of [] -> Bad("no case was run"); _ -> ok end,
    B = fun(<<"-">>) -> <<>>; (H) -> binary:decode_hex(H) end,
    V = fun(Pk, Sig, Msg) -> try crypto:verify(mldsa87, none, Msg, Sig, Pk) of R -> R =:= true catch _:_ -> false end end,
    Wrong = [Id || [Id, Pk, Sig, Msg, _, E] <- Run, V(B(Pk), B(Sig), B(Msg)) =/= (E =:= <<"1">>)],
    Ids = "[" ++ lists:join(",", [binary_to_list(I) || I <- Wrong]) ++ "]",
    [{_, _, Ver}] = crypto:info_lib(),
    io:format("Erlang/OTP ~s :crypto on ~s: ~p cases with the empty context, ~p disagree with the expected result ~s; ~p cases with a context not run (no context argument)~n",
              [erlang:system_info(otp_release), Ver, length(Run), length(Wrong), Ids, length(All) - length(Run)]),
    halt(case Wrong of [] -> 0; _ -> 1 end).
