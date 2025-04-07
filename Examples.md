# Examples

**For advanced administration topics** see the [Administration Guide](https://github.com/m3047/rkvdns/blob/main/Administration.md) and the [Configuration Guide](https://github.com/m3047/rkvdns/blob/main/Configuration.md).

**For additional examples** see [the examples](https://github.com/m3047/rkvdns_examples)

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

* **domain** is the service name (`redis-department.example.com`). In DNS parlance it is a _delegated zone_ and so it is indeed what is popularly referred to as a _domain_ although DNS has a simultaneously more specific and more generic meaning for the term. One way to think about it is to imagine it as the "Redis Department" which has its own nameserver(s) -- this service.

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

When you see something like `10\.0\.0\.224\;*\;flow.KEYS.redis.sophia.m3047.` the "\\" is being used to escape the dots
in `10.0.0.224` which is literally what we're looking for and what is actually written as the key value, along with
escaping ";" which in _zone file format_ is the comment marker.

## TTL (time to live)

Redis supports TTLs. If no TTL is available or makes sense (in the case of for example `KEYS`) the configured value
of `DEFAULT_TTL` is used.

Presently our key `foo` doesn't have a TTL:

```
# dig @10.0.0.224 foo.get.redis.sophia.m3047 TXT +noall +answer

; <<>> DiG 9.12.3-P1 <<>> @10.0.0.224 foo.get.redis.sophia.m3047 TXT +noall +answer
; (1 server found)
;; global options: +cmd
foo.get.redis.sophia.m3047. 30  IN      TXT     "bar"
```

Let's set it to expire:

```
>>> conn.expire('foo',111)
True
>>> 

# dig @10.0.0.224 foo.get.redis.sophia.m3047 TXT +noall +answer

; <<>> DiG 9.12.3-P1 <<>> @10.0.0.224 foo.get.redis.sophia.m3047 TXT +noall +answer
; (1 server found)
;; global options: +cmd
foo.get.redis.sophia.m3047. 109 IN      TXT     "bar"
```

When we retrieved it again we got the value `109` instead of `30`. We got 109 because a couple of seconds elapsed
from when I set expiry and when I repeated the lookup operation.

### TTLs and the WAF

If you put a caching resolver in front of the service, you'll see something rather different:

```
# dig foo.get.redis.sophia.m3047 TXT +noall +answer

; <<>> DiG 9.12.3-P1 <<>> foo.get.redis.sophia.m3047 TXT +noall +answer
;; global options: +cmd
foo.get.redis.sophia.m3047. 30  IN      TXT     "bar"
# dig foo.get.redis.sophia.m3047 TXT +noall +answer

; <<>> DiG 9.12.3-P1 <<>> foo.get.redis.sophia.m3047 TXT +noall +answer
;; global options: +cmd
foo.get.redis.sophia.m3047. 28  IN      TXT     "bar"
# dig foo.get.redis.sophia.m3047 TXT +noall +answer

; <<>> DiG 9.12.3-P1 <<>> foo.get.redis.sophia.m3047 TXT +noall +answer
;; global options: +cmd
foo.get.redis.sophia.m3047. 26  IN      TXT     "bar"
```

Here we see that the TTL is counting down from the default value. The caching resolver fetched the answer the
first time we asked (and returned the default TTL of 30), and then every time we ask again it gives us a
decrementing TTL until it expires, at which point it fetches the answer again.

## Case Folding

The DNS is _case insensitive_: it treats upper and lower case letters the same. This only applies to ASCII,
it doesn't understand Unicode (punycode doesn't count). Due to caching and other things, the query you send to a
caching resolver may have different case when it reaches the actual service. Redis is _case sensitive_.

To address this, we support _case folding_. The following folding modes are supported with `CASE_FOLDING`:

* (literal) `None`: no folding
* `'lower'`: force lower case
* `'upper'`: force upper case
* `'escape'`: use per-character folding with escapes

In the first example, my keys all look like `<address>;<address>;<port>;flow`. `flow` is an actual lower case literal.
(There are some others but this is the one we're interested in. Conveniently all of them are lower case!)
    
I have the service configured with `CASE_FOLDING = 'lower'`.

## Addresses

Most people's familiarity with the DNS concerns addresses, or `A` (IPv4) and `AAAA` (IPv6) records. There are other
types. The service supports three types of records:

* `TXT` Text data
* `A` IPv4 addresses
* `AAAA` IPv6 addresses

If you go back and look, you'll see I specified `TXT` in all of the examples. `A` is the default type if nothing is
specified.

**TIP: If you're not getting data and it's not an address, did you specify `TXT` in the query?**

How does this work?

```
>>> conn.set('foo','1.2.3.4')
True
>>> 
# dig foo.get.redis.sophia.m3047

; <<>> DiG 9.12.3-P1 <<>> foo.get.redis.sophia.m3047
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33021
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1280
; COOKIE: bc844ea008ac880d51f7054e62cb04c2dbb8afc76c93a38e (good)
;; QUESTION SECTION:
;foo.get.redis.sophia.m3047.    IN      A

;; ANSWER SECTION:
foo.get.redis.sophia.m3047. 30  IN      A       1.2.3.4

;; AUTHORITY SECTION:
REDIS.SOPHIA.m3047.     600     IN      NS      SOPHIA.M3047.

;; ADDITIONAL SECTION:
SOPHIA.m3047.           600     IN      A       10.0.0.224

;; Query time: 29 msec
;; SERVER: 10.0.0.220#53(10.0.0.220)
;; WHEN: Sun Jul 10 09:56:34 PDT 2022
;; MSG SIZE  rcvd: 159
```

Works pretty well!

## Native Integer Type Support

The DNS supports _big endian_ 32 bit and 128 bit integers natively. That's what an IPv4 or IPv6 address is, respectively.

```
>>> conn.delete('foo')
1
>>> conn.incr('foo')
1
>>> conn.incr('foo')
2
>>> conn.incr('foo')
3

 dig @sophia.m3047 foo.get.redis.sophia.m3047

; <<>> DiG 9.12.3-P1 <<>> @sophia.m3047 foo.get.redis.sophia.m3047
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4412
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1200
;; QUESTION SECTION:
;foo.get.redis.sophia.m3047.    IN      A

;; ANSWER SECTION:
foo.get.redis.sophia.m3047. 30  IN      A       0.0.0.3

;; Query time: 6 msec
;; SERVER: 10.0.0.224#53(10.0.0.224)
;; WHEN: Sun Jul 10 10:54:12 PDT 2022
;; MSG SIZE  rcvd: 71
```

I know, it's underwhelming. Here we will make a Python `ipaddress.IPv4Address` from a
"dotted quad" string, and then convert that to an integer. We will then use the base 10
integer value to set the redis key:

```
>>> addr = ip_address('1.2.3.4')
>>> int(addr)
16909060
>>> conn.set('foo',int(addr))
True
# dig @sophia.m3047 foo.get.redis.sophia.m3047 +noall +answer

; <<>> DiG 9.12.3-P1 <<>> @sophia.m3047 foo.get.redis.sophia.m3047 +noall +answer
; (1 server found)
;; global options: +cmd
foo.get.redis.sophia.m3047. 30  IN      A       1.2.3.4
```

We're almost there. If we convert the integer address to big endian bytes, we get
`b'\x01\x02\x03\x04'`! We can see looking at wire format in `dnspython` that it agrees
that this is wire format for the number.

In case you are wondering, this is where dotted quad notation comes from.

```
>>> int(addr).to_bytes(4,'big')
b'\x01\x02\x03\x04'
>>> resp = resolver.query('foo.get.redis.sophia.m3047.','A')
>>> resp.response.answer[0][0]
<DNS IN A rdata: 1.2.3.4>
>>> bio = BytesIO()
>>> resp.response.answer[0][0].to_wire(bio)
>>> bio.seek(0)
0
>>> bio.read()
b'\x01\x02\x03\x04'
>>> 
```

For the record, although I use `dnspython` in the service I really wouldn't recommend it for integer support
in production. If you use a library which lets you access wire data, the conversion is going to look more like
`value = int.from_bytes(buffer[i:i+4], 'big')` in raw Python. Maybe you don't want to use Python at all. :-/

-------------------

For paid support: fwm.rkvdns.support.f2u@m3047.net
