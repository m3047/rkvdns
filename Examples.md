# Examples

## The Gleam in My Eye

This is the example given in the README. I run [ShoDoHFlo](https://github.com/m3047/shodohflo) and it maintains a
_Redis_ database of DNS lookups and netflows attributable to clients.

I want to get to the netflow information from random locations on my network. I don't want to install a redis client
everywhere, plus I know DNS. Hammer, meet nail.

You are going to need to learn a few things about DNS. The `pydoc` will prove helpful, we'll try to give other pointers
as needed. In particular, look `pydoc3 agent`. (NOTE: you will need to `cd python` first) `pydoc3 rkvdns.io` has some
discussion of DNS optimization.

TIP: You can enable and run `tests/end_to_end.py` and examine the DNS traffic with wireshark for a low level look at
what's going on.

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
# dig @sophia.m3047 '10\.0\.0\.224;*;flow.KEYS.redis.sophia.m3047.' TXT

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

## Syntax

You may be thinking, "I know what `redis.sophia.m3047` is, I can guess what `KEYS` is, but what the heck is all of
the whack, slash and punctuation?"

First off, you're on the right track. The overall construction of the query name looks like:

    <optional-parameter>.<key-or-pattern>.<operator>.<domain>
    
From right to left:

* **domain** is the service or nameserver name. In DNS parlance it is a _delegated zone_ and so it is indeed what is popularly referred to as a _domain_ although DNS has a simultaneously more specific and more generic meaning for the term.

The other parts are "things in the domain":

* **operator** a redis operator.
* **key-or-pattern** what you're looking for.
* **optional-parameter** an additional parameter for some operations, such as an index, hash key or range.

Let's start with a simpler query and then revisit this one. We are going to do this in Python and query the service,
not the WAF, directly.

```
>>> import redis
>>> conn = redis.client.Redis('10.0.0.224')                         
>>> import dns.resolver as resolver
>>> conn.set('foo','bar')
True
>>> conn.get('foo')
b'bar'
>>> resp = resolver.query('foo.get.redis.sophia.m3047','TXT')
>>> resp
<dns.resolver.Answer object at 0x7f74e318e9e8>
>>> resp.response
<DNS message, ID 2467>
>>> resp.response.answer[0][0]
<DNS IN TXT rdata: "bar">
>>> 
```

Repeating the same query with `dig`:

```
# dig @10.0.0.224 foo.get.redis.sophia.m3047 TXT

; <<>> DiG 9.12.3-P1 <<>> @10.0.0.224 foo.get.redis.sophia.m3047 TXT
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2545
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1200
;; QUESTION SECTION:
;foo.get.redis.sophia.m3047.    IN      TXT

;; ANSWER SECTION:
foo.get.redis.sophia.m3047. 30  IN      TXT     "bar"

;; Query time: 4 msec
;; SERVER: 10.0.0.224#53(10.0.0.224)
;; WHEN: Sun Jul 10 09:07:49 PDT 2022
;; MSG SIZE  rcvd: 71
```

### Back to our original example

You're almost never going to be able to deal with DNS directly on the wire, you're always going to have to
do it through some tool. For whatever it's worth, `dig` command output in the above example is colloquially called
"zone file format".

So here's the deal. As far as the DNS is concerned, the dots in `foo.get.redis.sophia.m3047.` don't exist; they're
visual separators for the _labels_, which is what the DNS stores and uses.

When you see something like `10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047.` the "\" is being used to escape the dots
in `10.0.0.224` which is literally what we're looking for and what is actually written as the key value, along with
escaping ";" which in _zone file format_ is the comment marker.
