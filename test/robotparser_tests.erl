-module(robotparser_tests).
-include_lib("eunit/include/eunit.hrl").

disallow0_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: /\n">>),
	false = Rb:is_allowed("/"),
	false = Rb:is_allowed("path"),
	false = Rb:is_allowed("//example.com/"),
	false = Rb:is_allowed("?432").

disallow1_test() ->
	Rb = robotparser:parse(<<>>),
	true = Rb:is_allowed("/"),
	true = Rb:is_allowed("path"),
	true = Rb:is_allowed("//example.com/"),
	true = Rb:is_allowed("?432").

disallow2_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: /test">>),
	true = Rb:is_allowed("/tes"),
	true = Rb:is_allowed("/"),
	true = Rb:is_allowed("path"),
	true = Rb:is_allowed("//example.com/"),
	true = Rb:is_allowed("?432").

disallow3_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow:">>),
	true = Rb:is_allowed("/foo/bar").

allow_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nAllow: /test\nDisallow: /t\nAllow: /tratata\nDisallow: /p">>),
	true  = Rb:is_allowed("/test"),
	false = Rb:is_allowed("/tra"),
	true  = Rb:is_allowed("/tratata"),
	true  = Rb:is_allowed("tratata"),
	true  = Rb:is_allowed("at").

agent_test() ->
	Rb = robotparser:parse(<<"User-Agent: bot\nDisallow: /">>),
	false = Rb:is_allowed("bot", "/"),
	false = Rb:is_allowed("testbot", "/"),
	false = Rb:is_allowed("bottest", "/"),
	true  = Rb:is_allowed("crawler", "/").

woroot_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nDisallow: tra\nAllow: tratata\nAllow: foo*bar">>),
	true = Rb:is_allowed("/tratata"),
	true = Rb:is_allowed("/foo/tratata/bar"),
	true = Rb:is_allowed("/foo/tra/bar"),
	false = Rb:is_allowed("/trata").

unicode_support_test() ->
	Rb = robotparser:parse(unicode:characters_to_binary("User-Agent: *\nDisallow: /œ̃")),
	false = Rb:is_allowed("/œ̃"),
	true = Rb:is_allowed("/øœé").

delay_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nCrawl-Delay: 10">>),
	10 = Rb:is_allowed("/").

agent_delay_test() ->
	Rb = robotparser:parse(<<
"User-Agent: crawler
Disallow: /search
Crawl-Delay: 10

User-Agent: bot
Crawl-Delay: 5

User-Agent: *">>),
	false = Rb:is_allowed("crawler", "/search"),
	10    = Rb:is_allowed("crawler", "/path"),
	5     = Rb:is_allowed("bot", "/"),
	true  = Rb:is_allowed("/").

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
	false = Rb:is_allowed("/tratata"),
	true  = Rb:is_allowed("/"),
	true  = Rb:is_allowed("nlcrawler", "/path"),
	true  = Rb:is_allowed("nlcrawler", "/pathtratata"),
	true  = Rb:is_allowed("nlcrawler", "/patratatah"),
	false = Rb:is_allowed("nlcrawler", "/pugh"),
	false = Rb:is_allowed("nlcrawler", "/pughtratata").

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
	false = Rb:is_allowed("bot/1.0", "/path"),
	true  = Rb:is_allowed("testcrawler/1.1", "/"),
	true  = Rb:is_allowed("tratata crawler/2.0", ""),
	false = Rb:is_allowed("crawler/3.0", "/search?q=tratata"),
	true  = Rb:is_allowed("tratata", "/"),
	true  = Rb:is_allowed("user", "/").

comment_test() ->
	Rb = robotparser:parse(<<
"User-Agent: * # tratata
Allow: /foo/bar # tratata
Disallow: /foo # tratata
# tratata">>),
	false = Rb:is_allowed("/foo"),
	true  = Rb:is_allowed("/foo/bar"),
	true  = Rb:is_allowed("/").

root_allow_test() ->
	Rb = robotparser:parse(<<"User-Agent: *\nAllow: /\nDisallow: /foo\nDisallow: /bar">>),
	true  = Rb:is_allowed("/"),
	true  = Rb:is_allowed("/tratata"),
	false = Rb:is_allowed("/foo"),
	false = Rb:is_allowed("/bar").

empty_ua_test() ->
	Rb0 = robotparser:parse(<<"User-Agent: *\nDisallow: /test">>),
	false = Rb0:is_allowed("/test"),
	Rb1 = robotparser:parse(<<"User-Agent:\nDisallow: /test">>),
	false = Rb1:is_allowed("/test").

code_test() ->
	Text  = crypto:rand_bytes(4096),

	Rb404 = robotparser:parse(Text, 404),
	true  = Rb404:is_allowed("/"),

	Rb403 = robotparser:parse(Text, 403),
	true = Rb403:is_allowed("/"),

	Rb503 = robotparser:parse(Text, 503),
	false  = Rb503:is_allowed("/"),

	RbR   = robotparser:parse(Text),
	true  = RbR:is_allowed("/").
