%% Copyright (c) 2011, 2012 Sergey Urbanovich
%% http://github.com/urbanserj/robotparser
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to deal
%% in the Software without restriction, including without limitation the rights
%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%% copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%% THE SOFTWARE.

-module(robotparser).
-export([parse/1, parse/2, is_allowed/2, is_allowed/3]).

-type url_t() :: binary() | {'pattern', binary()}.
-type rule_t() :: {'allow' | 'disallow', url_t()}.

-type url() :: binary() | string().
-type agent() :: binary() | string().
-type allowed() :: boolean() | non_neg_integer().

-record('User-Agent', {
	agent = <<"*">> :: binary(),
	delay = true :: 'true' | integer(),
	rules = [] :: [rule_t()]
}).
-record(robotparser, {
	list = [] :: [#'User-Agent'{}]
}).

-type robotparser() :: #robotparser{}.
-export_type([robotparser/0]).


-spec parse(binary(), integer()) -> robotparser().
parse(_Text, Code) when Code >= 500 ->
	#robotparser{list =
		[#'User-Agent'{delay = false, rules = [{disallow, <<"/">>}]}]
	}; % 40x -> disallow
parse(_Text, Code) when Code >= 400 ->
	#robotparser{list = []};
parse(Text, _Code) when byte_size(Text) > 262144 -> % 256kb
	#robotparser{list = []};
parse(Text, _Code) ->
	parse(Text).


-spec parse(binary()) -> robotparser().
parse(Text) ->
	% split lines
	BinLines = binary:split(Text, [<<"\r\n">>, <<"\n">>,
	                               <<"\n\r">>, <<"\r">>], [global, trim]),
	Lines = [strip_binary(to_lower(remove_comments(X))) || X <- BinLines],
	parse_lines(Lines, []).


-spec parse_lines([binary()], [#'User-Agent'{}]) -> robotparser().
parse_lines([], Us) ->
	RL = [U#'User-Agent'{ rules = sort(U#'User-Agent'.rules) } || U <- Us],
	#robotparser{list = uasort(RL)};
parse_lines([<<>>|Lines], Us) ->
	% skip empty
	parse_lines(Lines, Us);
parse_lines([<<$#, _/binary>>|Lines], Us) ->
	% skip comments
	parse_lines(Lines, Us);
parse_lines([Line|Lines], Us) ->
	% try to match "Directive: Value"
	[D|R] = binary:split(Line, <<":">>, [trim]),
	Ds = strip_binary(D, tail),
	try strip_binary(hd(R), head) of
		<<>> ->
			parse_lines(Lines, Us);
		Rs when Ds =:= <<"user-agent">> ->
			parse_lines(Lines, add_rule(Us, {agent, Rs}));
		Rs when Ds =:= <<"disallow">> ->
			parse_lines(Lines, add_rule(Us, {disallow, is_pattern(Rs)}));
		Rs when Ds =:= <<"allow">> ->
			parse_lines(Lines, add_rule(Us, {allow, is_pattern(Rs)}));
		Rs when Ds =:= <<"crawl-delay">> ->
			Delay = binary_to_integer(Rs),
			parse_lines(Lines, add_rule(Us, {delay, Delay}));
		_ ->
			parse_lines(Lines, Us)
	catch
		_:_ when Ds =:= <<"user-agent">> ->
			parse_lines(Lines, add_rule(Us, {agent, <<$*>>}));
		_:_ ->
			parse_lines(Lines, Us)
	end.


-spec is_allowed(robotparser(), url()) -> allowed().
is_allowed(Rb, Url) ->
	is_allowed(Rb, Url, <<"*">>).

-spec is_allowed(robotparser(), url(), agent() | undefined) -> allowed().
is_allowed(Rb, Url, Agent) when is_list(Agent) ->
	is_allowed(Rb, Url, list_to_binary(Agent));
is_allowed(Rb, Url, Agent) ->
	is_allowed_n(Rb, to_lower(Url), Agent).

-spec is_allowed_n(robotparser(), url(), agent() | undefined) -> allowed().
is_allowed_n(_Rb, <<"/robots.txt">>, _Agent) ->
	true;
is_allowed_n(Rb, <<"">>, Agent) ->
	is_allowed_n(Rb, <<"/">>, Agent);
is_allowed_n(Rb, <<H:8, _/binary>> = Url, Agent) when H =/= $/ ->
	is_allowed_n(Rb, <<$/, Url/binary>>, Agent);
is_allowed_n(Rb, Url, <<"">>) ->
	is_allowed_n(Rb, Url, <<"*">>);
is_allowed_n(Rb, Url, undefined) ->
	is_allowed_n(Rb, Url, <<"*">>);
is_allowed_n(#robotparser{list = List}, Url, Agent) ->
	match_agent(Agent, Url, List).


-spec match_agent(binary(), binary(), [#'User-Agent'{}])
		-> integer() | boolean().
match_agent(_Agent, _Url, []) ->
	true;
match_agent(Agent, Url, [L|Ls]) ->
	case binary:match(Agent, L#'User-Agent'.agent) of
		nomatch when L#'User-Agent'.agent =/= <<"*">> ->
			match_agent(Agent, Url, Ls);
		_ ->
			match_url(L, Url)
	end.


-spec match_url(#'User-Agent'{}, binary()) -> integer() | boolean().
match_url(#'User-Agent'{rules = [{Type, R}|Rs]} = U, Url) ->
	case match(Url, R) of
		true  ->
			case Type of
				allow -> U#'User-Agent'.delay;
				disallow -> false
			end;
		false -> match_url(U#'User-Agent'{rules = Rs}, Url)
	end;
match_url(U, _Url) ->
	U#'User-Agent'.delay.


-spec add_rule([#'User-Agent'{}], rule_t() | {'agent', binary()} |
	{'delay', undefined | integer()}) -> [#'User-Agent'{}].
add_rule(Us, {agent, UA}) ->
	[#'User-Agent'{agent=UA}|Us];
add_rule([], _) ->
	[];
add_rule(Us, {delay, undefined}) ->
	Us;
add_rule([U|Us], {delay, Delay}) ->
	[U#'User-Agent'{delay=Delay}|Us];
add_rule([U=#'User-Agent'{rules=Rules}|Us], Rule) ->
	[U#'User-Agent'{rules=[Rule|Rules]}|Us].

% utils

-spec strip_binary(binary()) -> binary().
strip_binary(Bin) ->
	Bin2 = strip_binary(Bin, head),
	strip_binary(Bin2, tail).

-spec strip_binary(binary(), 'head' | 'tail') -> binary().
strip_binary(<<>>, _) ->
	<<>>;
strip_binary(<<" ", Bin/binary>>, head) ->
	strip_binary(Bin, head);
strip_binary(Bin, tail) ->
	case binary:last(Bin) of
		32 ->
			Bin2 = binary:part(Bin, {0, byte_size(Bin) - 1}),
			strip_binary(Bin2, tail);
		_  ->
			Bin
	end;
strip_binary(Bin, _) ->
	Bin.


-spec remove_comments(binary()) -> binary().
remove_comments(Bin) ->
	hd(binary:split(Bin, <<$#>>)).

-spec to_lower(binary() | string()) -> binary().
to_lower(Str) when is_list(Str) ->
	to_lower(unicode:characters_to_binary(Str));
to_lower(Bin) ->
	<< <<(lower(C))>> || <<C:8>> <= Bin >>.

-spec lower(byte()) -> byte().
lower($A) -> $a;
lower($B) -> $b;
lower($C) -> $c;
lower($D) -> $d;
lower($E) -> $e;
lower($F) -> $f;
lower($G) -> $g;
lower($H) -> $h;
lower($I) -> $i;
lower($J) -> $j;
lower($K) -> $k;
lower($L) -> $l;
lower($M) -> $m;
lower($N) -> $n;
lower($O) -> $o;
lower($P) -> $p;
lower($Q) -> $q;
lower($R) -> $r;
lower($S) -> $s;
lower($T) -> $t;
lower($U) -> $u;
lower($V) -> $v;
lower($W) -> $w;
lower($X) -> $x;
lower($Y) -> $y;
lower($Z) -> $z;
lower(Char) -> Char.


-spec binary_to_integer(binary()) -> integer() | 'undefined'.
binary_to_integer(Bin) ->
	binary_to_integer(Bin, 0).

-spec binary_to_integer(binary(), integer()) -> integer() | 'undefined'.
binary_to_integer(<<>>, Acc) ->
	Acc;
binary_to_integer(<<C:8, Bin/binary>>, Acc)
	when C >= $0, C =< $9 -> binary_to_integer(Bin, Acc*10+C-$0);
binary_to_integer(_Bin, _Acc) ->
	undefined.

-spec match(binary(), url_t()) -> boolean().
match(Bin, {pattern, Pattern}) ->
	match_pattern(Bin, Pattern);
match(_Bin, <<>>) ->
	false;
match(_Bin, <<$/>>) ->
	true;
match(Bin, <<$/, Pattern/binary>>) ->
	case binary:match(Bin, Pattern) of
		{1, _} -> true;
		_ -> false
	end;
match(Bin, Pattern) ->
	case binary:match(Bin, Pattern) of
		nomatch -> false;
		_ -> true
	end.

-spec match_pattern(binary(), binary()) -> boolean().
match_pattern(_Bin, <<>>) ->
	true;
match_pattern(<<>>, <<$$>>) ->
	true;
match_pattern(Bin, <<$$>>) when byte_size(Bin) > 0 ->
	false;
match_pattern(_Bin, <<$$, Pattern/binary>>) when byte_size(Pattern) > 0 ->
	false;
match_pattern(Bin, <<$*, Pattern/binary>>) ->
	match_pattern_ast(Bin, Pattern);
match_pattern(<<C:8, Bin/binary>>, <<C:8, Pattern/binary>>) ->
	match_pattern(Bin, Pattern);
match_pattern(_Bin, _Pattern) ->
	false.

-spec match_pattern_ast(binary(), binary()) -> boolean().
match_pattern_ast(<<>>, <<>>) ->
	true;
match_pattern_ast(<<>>, <<$$>>) ->
	true;
match_pattern_ast(<<C:8, Bin/binary>>, Pattern) ->
	case match_pattern(<<C:8, Bin/binary>>, Pattern) of
		true -> true;
		false -> match_pattern_ast(Bin, Pattern)
	end;
match_pattern_ast(_Bin, _Pattern) ->
	false.


-spec is_pattern(binary()) -> url_t().
is_pattern(<<S, Bin/binary>>) when S =/= $/ ->
	is_pattern(<<$/, S, Bin/binary>>);
is_pattern(Bin) ->
	case binary:match(Bin, [<<$*>>, <<$$>>]) of
		nomatch -> Bin;
		_ -> {pattern, Bin}
	end.

-spec sort([rule_t()]) -> [rule_t()].
sort(Rules) ->
	lists:sort( fun({_, A}, {_, B}) ->
		case is_binary(A) and is_binary(B) of
			true -> byte_size(A) > byte_size(B);
			false -> true
		end
	end, Rules ).

-spec uasort([#'User-Agent'{}]) -> [#'User-Agent'{}].
uasort(List) ->
	lists:sort( fun(#'User-Agent'{agent=A}, #'User-Agent'{agent=B}) ->
		byte_size(A) > byte_size(B)
	end, List ).
