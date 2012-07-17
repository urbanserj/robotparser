-module(robotparser_tests).
-include_lib("eunit/include/eunit.hrl").

-define(T(Expr), ?assert(Expr)).
-define(F(Expr), ?assertNot(Expr)).
-define(E(A, B), ?assertEqual(A, B)).

disallow0_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: /\n">>),
	?F(robotparser:is_allowed(Rb, "/")),
	?F(robotparser:is_allowed(Rb, "path")),
	?F(robotparser:is_allowed(Rb, "//example.com/")),
	?F(robotparser:is_allowed(Rb, "?432")).

disallow1_test() ->
	Rb = robotparser:parse(<<>>),
	?T(robotparser:is_allowed(Rb, "/")),
	?T(robotparser:is_allowed(Rb, "path")),
	?T(robotparser:is_allowed(Rb, "//example.com/")),
	?T(robotparser:is_allowed(Rb, "?432")).

disallow2_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: /test">>),
	?T(robotparser:is_allowed(Rb, "/tes")),
	?T(robotparser:is_allowed(Rb, "/")),
	?T(robotparser:is_allowed(Rb, "path")),
	?T(robotparser:is_allowed(Rb, "//example.com/")),
	?T(robotparser:is_allowed(Rb, "?432")).

disallow3_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow:">>),
	?T(robotparser:is_allowed(Rb, "/foo/bar")).

allow_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nAllow: /test\nDisallow: /t\nAllow: /tratata\nDisallow: /p">>),
	?T(robotparser:is_allowed(Rb, "/test")),
	?F(robotparser:is_allowed(Rb, "/tra")),
	?T(robotparser:is_allowed(Rb, "/tratata")),
	?T(robotparser:is_allowed(Rb, "tratata")),
	?T(robotparser:is_allowed(Rb, "at")).

agent_test() ->
	Rb = robotparser:parse(<<"User-Agent: bot\nDisallow: /">>),
	?F(robotparser:is_allowed(Rb, "/", "bot")),
	?F(robotparser:is_allowed(Rb, "/", "testbot")),
	?F(robotparser:is_allowed(Rb, "/", "bottest")),
	?T(robotparser:is_allowed(Rb, "/", "crawler")).

woroot_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: tra\nAllow: tratata\nAllow: foo*bar">>),
	?T(robotparser:is_allowed(Rb, "/tratata")),
	?T(robotparser:is_allowed(Rb, "/foo/tratata/bar")),
	?T(robotparser:is_allowed(Rb, "/foo/tra/bar")),
	?F(robotparser:is_allowed(Rb, "/trata")).

unicode_support_test() ->
	Rb = robotparser:parse(unicode:characters_to_binary("User-Agent: *\nDisallow: /œ̃")),
	?F(robotparser:is_allowed(Rb, "/œ̃")),
	?T(robotparser:is_allowed(Rb, "/øœé")).

delay_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nCrawl-Delay: 10">>),
	?E(robotparser:is_allowed(Rb, "/"), 10).

agent_delay_test() ->
	Rb = robotparser:parse(<<
"User-Agent: crawler
Disallow: /search
Crawl-Delay: 10

User-Agent: bot
Crawl-Delay: 5

User-Agent: *">>),
	?F(robotparser:is_allowed(Rb, "/search", "crawler")),
	?E(robotparser:is_allowed(Rb, "/path", "crawler"), 10),
	?E(robotparser:is_allowed(Rb, "/", "bot"), 5),
	?T(robotparser:is_allowed(Rb, "/")).

pattern_test() ->
	Rb = robotparser:parse(<<
"User-Agent: crawler
Disallow: /p*h
Disallow: /p*th$
Allow: /path
Allow: /pa*h$

User-Agent: *
Disallow: /
Allow: /$">>),
	?F(robotparser:is_allowed(Rb, "/tratata")),
	?T(robotparser:is_allowed(Rb, "/")),
	?T(robotparser:is_allowed(Rb, "/path", "nlcrawler")),
	?T(robotparser:is_allowed(Rb, "/pathtratata", "nlcrawler")),
	?T(robotparser:is_allowed(Rb, "/patratatah", "nlcrawler")),
	?F(robotparser:is_allowed(Rb, "/pugh", "nlcrawler")),
	?F(robotparser:is_allowed(Rb, "/pughtratata", "nlcrawler")).

mix_test() ->
	Robots_txt = <<"
User-Agent: bot
Disallow: /

User-Agent: crawler
Disallow: /path$
Disallow: /sea*rch

User-Agent: tratata
Disallow: /harming/humans
Disallow: /ignoring/human/orders
Disallow: /harm/to/self

User-Agent: user
Allow: /">>,
	Rb = robotparser:parse(Robots_txt),
	?F(robotparser:is_allowed(Rb, "/path", "bot/1.0")),
	?T(robotparser:is_allowed(Rb, "/", "testcrawler/1.1")),
	?T(robotparser:is_allowed(Rb, "", "tratata crawler/2.0")),
	?F(robotparser:is_allowed(Rb, "/search?q=tratata", "crawler/3.0")),
	?T(robotparser:is_allowed(Rb, "/", "tratata")),
	?T(robotparser:is_allowed(Rb, "/", "user")).

comment_test() ->
	Rb = robotparser:parse(<<
"User-Agent: * # tratata
Allow: /foo/bar # tratata
Disallow: /foo # tratata
# tratata">>),
	?F(robotparser:is_allowed(Rb, "/foo")),
	?T(robotparser:is_allowed(Rb, "/foo/bar")),
	?T(robotparser:is_allowed(Rb, "/")).

root_allow_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nAllow: /\nDisallow: /foo\nDisallow: /bar">>),
	?T(robotparser:is_allowed(Rb, "/")),
	?T(robotparser:is_allowed(Rb, "/tratata")),
	?F(robotparser:is_allowed(Rb, "/foo")),
	?F(robotparser:is_allowed(Rb, "/bar")).

empty_ua_test() ->
	Rb0 = robotparser:parse(<<"User-Agent: *\nDisallow: /test">>),
	?F(robotparser:is_allowed(Rb0, "/test")),
	Rb1 = robotparser:parse(<<"User-Agent:\nDisallow: /test">>),
	?F(robotparser:is_allowed(Rb1, "/test")).

code_test() ->
	Text  = crypto:rand_bytes(4096),

	Rb404 = robotparser:parse(Text, 404),
	?T(robotparser:is_allowed(Rb404, "/")),

	Rb403 = robotparser:parse(Text, 403),
	?T(robotparser:is_allowed(Rb403, "/")),

	Rb503 = robotparser:parse(Text, 503),
	?F(robotparser:is_allowed(Rb503, "/")),

	RbR   = robotparser:parse(Text),
	?T(robotparser:is_allowed(RbR, "/")).

binary_test() ->
	Rb = robotparser:parse(<<>>),
	?T(robotparser:is_allowed(Rb, <<"/">>, <<"crawler">>)).

ua_order_test() ->
	Rb = robotparser:parse(<<"
User-Agent: *
Disallow: /

User-Agent: bot
Disallow: /a
Disallow: /b

User-Agent: googlebot
Disallow: /a
	">>),
	?T(robotparser:is_allowed(Rb, <<"/">>, <<"googlebot">>)),
	?T(robotparser:is_allowed(Rb, <<"/b">>, <<"googlebot">>)),
	?F(robotparser:is_allowed(Rb, <<"/a">>, <<"googlebot">>)),
	?F(robotparser:is_allowed(Rb, <<"/b">>, <<"bot">>)),
	?F(robotparser:is_allowed(Rb, <<"/a">>, <<"bot">>)),
	?F(robotparser:is_allowed(Rb, <<"/">>, <<"crawler">>)).
