robotparser
===========

Parser for robots.txt

Usage
-----

	Erlang R15B01 (erts-5.9.1) [source] [smp:2:2] [async-threads:0] [kernel-poll:false]
	
	Eshell V5.9.1  (abort with ^G)
	1> inets:start().
	ok
	2> {ok, {{_, StatusCode, _}, _, Data}} = httpc:request(get, {"http://example.org/robots.txt", []}, [], [{body_format,binary}]).
	{ok,{{"HTTP/1.1",200,"OK"},
	     [{"server","tratata/1.0"}
	      {"content-length","57"},
	      {"content-type","text/plain"}],
	     <<"User-Agent: crawler\nDisallow:\n\nUser-Agent: *\nDisallow: /\n">>}}
	3> Rb = robotparser:parse(Data, StatusCode).
	{robotparser,[{'User-Agent',<<"crawler">>,true,
	                            [{disallow,<<>>}]},
	              {'User-Agent',<<"*">>,true,[{disallow,<<"/">>}]}]}
	4> robotparser:is_allowed(Rb, "/foo").
	false
	5> robotparser:is_allowed(Rb, "/bar", "crawler/1.0").
	true
