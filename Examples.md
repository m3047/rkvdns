# Examples

## The Gleam in My Eye

This is the example given in the README. I run [ShoDoHFlo](https://github.com/m3047/shodohflo) and it maintains a
_Redis_ database of DNS lookups and netflows attributable to clients.

I want to get to the netflow information from random locations on my network. I don't want to install a redis client
everywhere, plus I know DNS. Hammer, meet nail.

You are going to need to learn a few things about DNS. The `pydoc` will prove helpful, we'll try to give other pointers
as needed. In particular, look `pydoc3 agent`. (NOTE: you will need to `cd python` first) `pydoc3 rkvdns.io` has some
discussion of DNS optimization.

Here is more complete `dig` output. `dig` is a command line tool which ships with _BIND_ from ISC. It has many options
and is intended as a tool for locally debugging DNS issues.

```
# dig peers.sophia.m3047 txt

; <<>> DiG 9.12.3-P1 <<>> peers.sophia.m3047 txt
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51237
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 11, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1280
; COOKIE: 3bc1fd52ad786ef7e3c3911862ca08ac6a940f4c120b3980 (good)
;; QUESTION SECTION:
;peers.sophia.m3047.            IN      TXT

;; ANSWER SECTION:
PEERS.SOPHIA.M3047.     600     IN      CNAME   10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047.
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;185.199.109.154;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;192.30.255.112;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;44.237.239.70;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;140.82.113.22;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;34.120.208.123;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;140.82.113.21;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;140.82.113.25;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;192.30.255.116;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;192.30.255.113;443;flow"
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047. 30 IN TXT "10.0.0.224;185.199.108.133;443;flow"

;; AUTHORITY SECTION:
REDIS.SOPHIA.m3047.     600     IN      NS      SOPHIA.M3047.

;; ADDITIONAL SECTION:
SOPHIA.m3047.           600     IN      A       10.0.0.224

;; Query time: 21 msec
;; SERVER: 10.0.0.220#53(10.0.0.220)
;; WHEN: Sat Jul 09 16:01:00 PDT 2022
;; MSG SIZE  rcvd: 664
```

This isn't actually coming directly from the server, it's coming from _BIND_ running locally (on `10.0.0.220`) as a caching resolver.

The `CNAME` record gives a clue as to the actual query. The missing clue is that `redis.sophia.m3047` is in fact running on
`sophia.m3047` and there's a _delegation_ (DNS is decentralized) in place, and we'll talk about that later.

Meanwhile we can try making the query directly to `sophia.m3047`:

```
 dig @sophia.m3047 '10\.0\.0\.224;*;flow.KEYS.redis.sophia.m3047.' TXT

; <<>> DiG 9.12.3-P1 <<>> @sophia.m3047 10\.0\.0\.224;*;flow.KEYS.redis.sophia.m3047. TXT
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59071
;; flags: qr aa; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1200
;; QUESTION SECTION:
;10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047.        IN TXT

;; ANSWER SECTION:
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;192.30.255.113;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;192.30.255.112;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;140.82.113.21;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;185.199.108.133;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;192.30.255.116;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;44.237.239.70;443;flow"
10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047. 30 IN TXT "10.0.0.224;140.82.113.25;443;flow"

;; Query time: 27 msec
;; SERVER: 10.0.0.224#53(10.0.0.224)
;; WHEN: Sat Jul 09 16:07:59 PDT 2022
;; MSG SIZE  rcvd: 397
```

You can see that the caching resolver added some additional information. (Our WAF!)

### Syntax

You may be thinking, "I know what `redis.sophia.m3047` is, I can guess what `KEYS` is, but what the heck is all of
the whack, slash and punctuation?"

You're almost never going to be able to deal with DNS directly on the wire, you're always going to have to
do it through some tool.

Let's repeat that same query in _Python_ (although you're free to use the language and library of your choice!).

