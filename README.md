robotparser
===========

Parser for robots.txt

Usage
-----

	Erlang R14B04 (erts-5.8.4) [source] [smp:2:2] [rq:2] [async-threads:0] [kernel-poll:false]
	
	Eshell V5.8.3  (abort with ^G)
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
	4> Rb:is_allow("/foo").
	false
	5> Rb:is_allow("crawler/1.0", "/bar").
	true
