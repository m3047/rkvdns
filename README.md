# rkvdns
**DNS Caching/Reverse Proxy Server for Redis**

Tested with _Python_ 3.6 and 3.11; _dnspython_ 1.15 and 2.2.

In a nutshell:

```
# dig peers.sophia.m3047 txt +short
10\.0\.0\.224\;*\;FLOW.KEYS.REDIS.SOPHIA.M3047.
"10.0.0.224;192.30.255.117;443;flow"
"10.0.0.224;185.199.109.154;443;flow"
"10.0.0.224;192.30.255.113;22;flow"
"10.0.0.224;44.237.239.70;443;flow"
"10.0.0.224;140.82.113.21;443;flow"
"10.0.0.224;192.30.255.112;443;flow"
"10.0.0.224;192.30.255.113;443;flow"
"10.0.0.224;140.82.113.25;443;flow"
"10.0.0.224;185.199.108.133;443;flow"
"10.0.0.224;34.120.208.123;443;flow"
```

* [Here is a detailed explanation.](https://github.com/m3047/rkvdns/blob/main/Examples.md)

***Use any DNS library. In any language. Async, or sync.*** Honey badger don't care.

* [The cybersecurity / observability value proposition.](http://consulting.m3047.net/pfs-why/)

In case you're looking for a checklist to scope your own DNS server project, here's the checklist I wish I'd had when I wrote this:

* [DNS Server Implementation Checklist](http://consulting.m3047.net/dubai-letters/dns-server-checklist.html)

### DNS Scale and Failover

DNS scales really well. It's a well understood problem. Many server implementations exist, and many scaling techniques as well.

### DNS Caching and TTLs

The whole point of DNS is to offload work. Caching is its middle name. Unsurprisingly it has _time to live_... just like Redis!

This service picks up TTLs from Redis and propagates them in the DNS cache.

### DNS WAF

DNS extensions such as _Response Policy Zones_ provide the equivalent of a Web Application Firewall, with access control and query filtering.

### The "Data Diode"

RKVDNS is strictly readonly, simplifying your attack surface assessment for Redis.

### Use it as DNS!

Sure, why not? If values can be converted to addresses, they will be returned for `A` and `AAAA` queries.

### Integer Support

DNS understands 32 and 128 bit integers (big endian) natively.

### Prerequisites

* Python 3.6 or better
* python `redis`
* `dnspython`
* `root` access in order to listen on a privileged port (port 53)

For production use you should put this behind a caching full service resolver such as _BIND_, _Unbound_ or _Knot_.

### Supported Redis Operations

The following operations are supported:

* `GET`
* `HGET`
* `HKEYS`
* `KEYS`
* `LINDEX`
* `LRANGE`
* `SMEMBERS`

##### "Length-of" Operators

The following "length-of" operators are supported. They return the number of elements (what would be TXT records) for
the underlying entry:

* `KLEN` -- The number of keys matching a pattern specified with `KEYS`.
* `KPLEN` -- "Key PREFIX length": like `KLEN` but without the need for a wildcard character at the end.
* `HLEN` -- The number of entries in a hash.
* `LLEN` -- The number of entries in a list.
* `SCARD` -- The number of entries in a set.

The only ones of these which doesn't correspond to a _Redis_ operator are `KLEN` and `KPLEN`.

-------------------

For paid support: fwm.rkvdns.support.f2u@m3047.net (That address... or alias... is real. It's a [Trualias](https://github.com/m3047/trualias/).)
