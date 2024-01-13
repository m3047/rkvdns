# Administration

_Read this with the_ [Configuration Guide]((https://github.com/m3047/rkvdns/blob/main/Configuration.md).

## Publishing Your Zone

The service is a nameserver as far as the DNS is concerned, and a nameserver is _authoritative_ for a zone.

A "zone" is what normal people call a "domain". Let's say my zone is `example.com`. I can create additional
records (the DNS calls all of these "domain names", but never mind) in that zone, at any level: `one.example.com`,
`one.two.example.com`, and so on.

I can also _delegate_ a zone, and I want to delegate that (sub) zone to the service. Let's call it `proxy.redis.example.com`.
(Maybe you have a `redis.example.com` already. Might that be a good place to run the service? It wouldn't actually conflict,
you'd be able to do it. Redis will listen on a different _port_ than DNS, so they can peacefully coexist.)

* The service is running on `redis.example.com`.
* The service is called `proxy.redis.example.com`.

You would add the equivalent of the following to the zone file for `example.com`:

```
REDIS.EXAMPLE.COM.        IN A    10.0.0.10
PROXY.REDIS.EXAMPLE.COM.  IN NS   REDIS.EXAMPLE.COM.
```

If you query a caching nameserver now, `foo.get.proxy.redis.example.com.` should do what you want.

The foregoing is not quite the whole story, although it will probably work. The DNS uses metadata
records to make informed decisions when it crosses zone boundaries, specifically the `SOA` and
`NS` records. There are two variables which you can set in `configuration.py` which will allow
_RKVDNS_ to synthesize these records:

* `RKVDNS_FQDN`: This is the nameserver FQDN. In the example above, this is `REDIS.EXAMPLE.COM`.
* `SOA_CONTACT`: This is the email address of the party responsible for administering the zone or service.

### In-zone nameservers

In general the same `NS` record(s) published "above the (zone) cut" or delegation should also
be published within the delegated zone. The DNS calls in-zone nameservers _in bailiwick_. The FQDN
for the record at the top or _apex_ of a delegated zone is colloquially referred to as the _domain_,
although internally the DNS specification refers to all FQDNs as "domains".

```
PROXY.REDIS.EXAMPLE.COM IN NS   REDIS.EXAMPLE.COM.
```

This is literally the same as what you published in the zone file for `example.com` above the zone
cut or delegation. In `configuration.py` you should assign the FQDN for the RKVDNS server to the
variable `RKVDNS_FQDN`. _RKVDNS_ uses the value of `ZONE` for the lefthand side (owner name) of the `NS` record and the value of
`RKVDNS_FQDN` for the righthand side (rdata).

So for instance the `NS` record shown above is synthesized from the following two configuration
variable settings:

```
ZONE = 'PROXY.REDIS.EXAMPLE.COM'
RKVDNS_FQDN = 'REDIS.EXAMPLE.COM'
```

### SOA record

___The service DOES NOT support zone transfers.___

The other magic record is the `SOA` record, which is also published at the apex of the delegated zone.
Some DNS servers or services may check for the presence of an `SOA` record to determine whether a
delegation is "valid" or not.

The other thing that the `SOA` record provides is information for automating zone data transfers; _RKVDNS_
does not support zone transfers.

```
PROXY.REDIS.EXAMPLE.COM IN SOA  REDIS.EXAMPLE.COM. DNS-ADMIN.EXAMPLE.COM. 1 30 30 86400 5
```

The `SOA_CONTACT` value is required to synthesize this record. That particular `SOA` record will be synthesized
from the following configuration variable settings:

```
MIN_TTL = 5
DEFAULT_TTL = 30
ZONE = 'PROXY.REDIS.EXAMPLE.COM'
RKVDNS_FQDN = 'REDIS.EXAMPLE.COM'
SOA_CONTACT = 'DNS-ADMIN.EXAMPLE.COM'
```

**NOTE:** The `@` sign is replaced with a `.` in the email address, so `dns-admin@example.com` should be
specified as `dns-admin.example.com`.

## A pretty name

Maybe you need a shorter and more memorable name, or the selection criteria is subject to change.

In that case you should set up a _canonical name_. You could add the following to the zone file for
`example.com`:

```
FOO.REDIS.EXAMPLE.COM.  IN CNAME  foo.get.proxy.redis.example.com.
```

It doesn't have to be in the same domain. For instance you could add the following to the
zone file for `example.net`:

```
FOO.REDIS.EXAMPLE.NET.  IN CNAME  foo.get.proxy.redis.example.com.
```

## Zone Admin with Response Policy Zones

_Response Policy Zones_ (RPZ) are an extension of DNS mostly used as a "DNS firewall", although they have some
other uses. We are going to demonstrate some of those uses now!

You should be running RPZ on a caching nameserver. You will need to query that nameserver or a nameserver which forwards
to it for this to work.

In all cases below, the records are intended to go into one or more locally administered RPZs. RPZs have a precedence or
application order. Below when we refer to the "first" or "second" RPZ we are referring to the order in which the RPZs are
processed. Oftentimes the first one is called the white or allow list and the second one is called the black or deny list.

**Read the instructions and follow carefully**

By this I mean the instructions for setting up and administering RPZ according to your DNS server. The examples below
refer to what goes _in_ the RPZ (the intended record), but that's not necessarily what's in the zone file _for_ the RPZ.

As an example: "I want to block anything under the `.PANGOLIN` top-level domain (which doesn't exist... yet... in ICANN's DNS scheme)".

For example `foo.pangolin` is blocked as "does not exist" (luckily the extended syntax hooks are pretty much the same
across RPZ implementations):

```
# dig foo.pangolin

;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 58459

;; QUESTION SECTION:
;foo.pangolin.                  IN      A

;; ADDITIONAL SECTION:
rpz1.m3047.net.         1       IN      SOA     DEV.NULL. M3047.M3047.NET. 387 600 60 86400 600
```

The rule is in an RPZ (zone) named `rpz1.m3047.net`. That RPZ is served/managed on a _BIND_ server. The zone contains
the following actual record:

```
# dig *.pangolin.rpz1.m3047.net

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15804

;; QUESTION SECTION:
;*.pangolin.rpz1.m3047.net.     IN      A

;; ANSWER SECTION:
*.PANGOLIN.rpz1.m3047.net. 600  IN      CNAME   .
```

If this was one of the following examples I would just refer to

```
*.PANGOLIN IN CNAME .
```

### DNS application firewall

#### Blocking an operator

Blocks the `KEYS` operator:

```
*.KEYS.PROXY.REDIS.EXAMPLE.COM IN CNAME  .
```

#### Allowing a specific query

You need to create two entries for this.

In the first RPZ, create the allow rule:

```
foo.GET.PROXY.REDIS.EXAMPLE.COM IN CNAME  rpz-passthru.
```

In the second RPZ, create the default deny rule:

```
*.PROXY.REDIS.EXAMPLE.COM  IN CNAME .
```

## Encryption

Plain old DNS is fast, but it's not encrypted.

You can pass the traffic over a VPN, and that's a common solution especially
for nameserver-to-nameserver traffic. There is no reason that the "authoritative" actual
service needs to be accessible to end users, it only needs to be reachable from the
caching resolver(s). Caching resolvers can be chained by forwarding from one resolver to
another.

There are options for encrypting traffic with end users: _DNS over HTTP(S)_ (DoH) and _DNS over TLS_ (DoT).
You need to have a DNS client / stub resolver which supports one of them.

_DoT_ support for the service is as simple as setting up _Nginx_ terminating TLS on port 853. See your
caching resolver's documentation for the mechanisms it supports.

## Errors as TXT

In some cases maybe you don't have access to the originating RKVDNS server's logs. Really you should
work on that. (If you can't query the RKVDNS server directly, the only error you may see is `SERVFAIL`.)

It is possible to turn (most) errors into "valid" DNS responses by setting `ENABLE_ERROR_TXT = True`.

If this is done, then the response is a `CNAME` pointing to a randomized `TXT` record with the actual
error description:

```
# dig @127.0.0.1 foo.bar.redis.sophia.m3047 txt
; <<>> DiG 9.12.3-P1 <<>> @127.0.0.1 foo.bar.redis.sophia.m3047 txt
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54780
;; flags: qr rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1200
;; QUESTION SECTION:
;foo.bar.redis.sophia.m3047.    IN      TXT

;; ANSWER SECTION:
foo.bar.redis.sophia.m3047. 30  IN      CNAME   511124793.error.redis.sophia.m3047.
511124793.error.redis.sophia.m3047. 30 IN TXT   "Parameter error: RedisOperandError()"

;; Query time: 3 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Mon Oct 24 17:08:58 PDT 2022
;; MSG SIZE  rcvd: 134
```

In this case `bar` was not a recognized operand.

## NXDOMAIN instead of SERVFAIL

If the data retrieved from a Redis query is impossibly large for DNS (exceeds `MAX_TCP_PAYLOAD`) and `RETURN_PARTIAL_TCP` is not enabled,
the server has returned a status of `SERVFAIL`. This is arguably the correct response (further information should be in the server logs),
however it doesn't propagate through caching resolvers reliably and may have undesirable side effects such as encouraging them to 
"try again"! Setting `NXDOMAIN_FOR_SERVFAIL` to `True` causes `NXDOMAIN` to be returned which has semantics which will cause the caching
resolver to conclude "this does not exist" for a short duration of time.

In-band signaling to the client is problematic in the DNS, see _Errors as TXT_ above.

## Marshalling and Debouncing

In the specific case of _RKVDNS_ deployments, a nameserver such as _BIND_ SHOULD be deployed in front of it as discussed
elsewhere in this document. Clients using _The DNS_ SHOULD be directed to such a server rather than accessing the
RKVDNS service directly.

Points in this section discuss mitigations due to poorly-behaved resolvers and poor systems-level thinking in the DNS community.
The behaviors at issue include:

* (Excessively) aggressive query retry over UDP.
* Retries which mint new query ids instead of re-using.
* A tendency to succumb to the "thundering herd".
* Privacy-motivated changes which result in an increased number of queries.

### Marshalling

The server performs _marshalling_: if multiple queries which come in which will result in the same _Redis_ query within a five
second window, the queries are collected in a tranche or flight and responded to collectively from a single _Redis_ query.

Separate flights are maintained for TCP versus UDP. For UDP, truncation may differ between observed responses and may not be optimal
in all cases if the advertised EDNS payload size varies between queries in the flight. In all such cases `TC=1` will be returned.

### Debouncing

If `DEBOUNCING = True` is specified in the configuration, the server performs debouncing of requests. Only the first UDP request
for a `( <peer-address>, <qname>, <qtype> )` tuple received in
a five second window is processed, subsequent requests for the same tuple in the window are dropped.

People may say this is "technically" incorrect: multiple clients on the peer host might coincidentally make the same request at
rougly the same time and this approach fails to take account of it. I have noticed that people who say "technically" generally haven't taken the
time to analyze the specific operating environment technically.

Technically, all clients on a host should be using the system resolver; hopefully it caches (see `nscd` although I have mixed feelings
about it).

### Disabling `qname-minimization`

Under the shibboleth of "privacy", some recursive resolvers opt to issue more less concise queries (instead of asking the intended
question of all authoritative servers consulted, they choose to ask vague questions which they conclude that particular server
should be able to answer). The problems with this approach revolve around DNS nodes called _empty non-terminals_.

_Empty non-terminals_ don't have records associated with them, but they have children; they DO NOT return `NXDOMAIN` because
they have children; or at least, they're not supposed to return `NXDOMAIN` although for other security reasons they often do.
"How can there be competing standards?" is a reasonable question, but bear in mind that a "Request For Comments" (RFC) is NOT
a standard; most of the internet is built on RFCs, and there are some things which are standards... in fact _Best Current Practice_
(BCP), which are routinely ignored. The Internet community is having a knife fight as it is wont to do from time to time.

_Empty non-terminals_ are relatively rare in the paths where resolving internet addresses (`A` and `AAAA` queries) are prevalent,
however they're common in more generic applications which rely on `TXT`, `SRV`, `PTR` and similar records. For instance,
`get.redis.example.com` (as opposed to `foo.get.redis.example.com`) would properly speaking be an _empty non-terminal_.

We recommend you disable `qname-minimization` (that's the _BIND_ configuration option) for data applications.

#### Don't name a key "_"

___Qname minimization___ **relies on the assumption that there will be no labels consisting of a single "`_`" character.**

Probes issued as part of _qname minimization_ are typically of the form `_.subzone.zone`: quite literally, a label of "_" is prepended and
a generic type `A` query is issued, attempting to elicit an `NXDOMAIN` response containing the zone's `SOA` record in the AUTHORITY section
of the response.

-------------------

For paid support: fwm.rkvdns.support.f2u@m3047.net
