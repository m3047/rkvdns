# Configuration Guide

Deployment of _RKVDNS_ will follow a process of:

1. Making sure it works.
2. Configuring the environment so that it can be found in your deployed DNS environment.
3. Making sure it works as well as possible with your recursive / caching DNS servers.

Each one of these phases may require adjusting one or more configuration parameters differently than at another stage in
the process. In particular, _RKVDNS_ includes verbose capabilities which may not conform to what your DNS service expects but
which are useful for debugging problems.

Some features of the modern, as-built DNS environment may conflict with debugging features and optimal performance. In particular,
two common features of recursive / caching infrastructure are noted as seemingly optimized for the `A` / `AAAA` (address resolution)
use case and can cause problems for data use cases:

* **Query Retransmission** was originally performed on the order of _seconds_ (i.e. one or two seconds) before retrying / retransmitting
  a query. At the present time some recursing resolvers may retransmit within _tens of milliseconds_. The original RFCs suggest that
  authoritative services should respond to all
  received queries individually to assist the recursive resolver in determining the best authoritative server to use. In most cases there
  will only be one authoritative server (_RKVDNS_ instance) for an _RKVDNS_ zone. Furthermore, answering duplicate queries would require
  repeatedly querying the _Redis_ database and building individualized responses, which can be expensive especially when a large number
  of records are returned: responding to retransmissions individually is undesirable in the data use case. (Immediate use of TCP instead
  of polite fallback from UDP would be the recommended mitigation for lost queries if traffic shaping won't work.)
* **Qname Minimization** is performed for the sake of privacy, in the sense of not broadcasting the entire question (which reveals
  a _Redis_ key) to every nameserver queried. In order to accomplish this, the recursing nameserver performs a game of "twenty questions" asking
  vague questions each of which elicits a little more information from the authoritative server(s) allowing it to proceed toward its
  resolution goal. In a "typical" deployment where two nameservers (a delegating authoritative server and an _RKVDNS_ instance) will need
  to be consulted this can cause **twice as many** DNS queries to be generated / answered than in the case where _qname minimization_ is
  not employed. Additionally an inconsistency in validation (non-functional requirements) is encountered: `strict` minimization employs
  some `NS` queries which will never be answered positively (there are no zones delegated from an _RKVDNS_ instance) however we cannot answer
  confidently with `NXDOMAIN` without performing a potentially expensive data lookup and so we have to answer with the more generic `ANSWER:0` + referral.

## Initial Deployment / Verification

During initial setup the questions you will be answering include:

* Does it talk to _Redis_?
* Does it retreve my keys / values?

Values to pay attention to at this phase are:

* Required for basic operation:
  * `INTERFACE` the network interface to listen on
  * `REDIS_SERVER` the address of the _Redis_ server to query
  * `ZONE` the zone in which we are publishing data
* `NXDOMAIN_FOR_SERVFAIL` turning this off will result in better error messages; not advisable in production
* `FOLDING` the case folding to employ
* `ALL_QUERIES_AS_TXT` ignores the query type and always treats it as `TXT` (the default for a lot of tools is `A`)
* `LOG_LEVEL` setting this to `logging.INFO` maximizes logging but may not be advisable in production
* `ENABLE_ERROR_TXT` returns error information encoded responses; not advisable in production
* `CONFORMANCE` alters error reporting for maximum compatibility with recursing resolvers; turn this off (`False`) during verification

In this phase you are validating that the _RKVDNS_ and _Redis_ servers can talk to each other and that your queries will
be responded to correctly. You will utilize a tool like `dig` or `nslookup` and query the _RKVDNS_ server directly, without
the intermediation of caching / recursing resolvers.

### `FOLDING`

You should decide on the case folding to employ at the outset. If you have no pre-existing _Redis_ keys and you're building from
the ground up I recommend starting with `FOLDING = 'lower'` and utilizing lower case _Redis_ keys.

## Environmental Setup

During this phase you will be "wiring it in" to your existing DNS architecture / infrastructure. Presumably you're not publishing this
to the internet at large (right?). The domain that you publish it in will be a nonpublished subdomain of a domain that you own, or a
private TLD.

Values to pay attention to at this phase are:

* Required for proper delegation:
  * `RKVDNS_FQDN` the FQDN for the _RKVDNS_ "name server".
  * `SOA_CONTACT` the contact address
* Additionally you will probably want to turn off:
  * `ALL_QUERIES_AS_TXT`
* ... and turn on:
  * `NXDOMAIN_FOR_SERVFAIL` caching resolvers oftentimes retry `SERVFAIL` queries with the presumption that the error is transient.
 
At this level `ENABLE_ERROR_TXT` typically doesn't cause any problems, although you'll probably want to disable it once you move to production. 

* The __delegating zone__ (served by the _delegating server_) is `example.com`.
* The __delegated zone__ (what _RKVDNS_ serves) is `rkvdns.example.com`.
* The _delegated zone_ is **served by** `redis.example.com`.
* The **contact for questions** is `admin@example.com` (which is encoded as `admin.example.com` according to the DNS specifications).

At the end of setup in this phase, you will be able to direct a query to the caching / recursing server and it will:

1. Query the _delegating server_ to locate the _RKVDNS_ zone.
2. Query the _RKVDNS server_ for data to return to you from the _RKVDNS_ zone.

I recommend you verify this with e.g. _Wireshark_ to familiarize yourself with the operation of the system.

With _qname minimization_ disabled, you would see three queries from the caching / recursing server to the authoritative servers
in our hypothetical deployment:

1. A `TXT` query to the _delegating server_ (`10.0.10.120` in our example below) for `foo.get.rkvdns.example.com` which returns ANSWER:0
   (NOERROR, but no answer) and an ADDITIONAL `NS` record for the domain `rkvdns.example.com` pointing at `redis.example.com` (a "referral").
2. An `A` query to the _delegating server_ to find the address for `redis.example.com`.
3. A `TXT` query for `foo.get.rkvdns.example.com` to `redis.example.com` (`10.0.1.11` in our example below) to get the data from _Redis_.

With _qname minimization_ active, you will see `NS` queries or `A` queries for various things above and below the zone cut. The only queries
which are the same from the case without _qname minimization_ are the `A` query to find the address for `redis.example.com` and the final `TXT`
query to retrieve the data from _Redis_.

### The delegating server

The _delegating server_ is authoritative for the zone from which the _RKVDNS_ zone is delegated. Assuming an _RKVDNS_ zone `rkvdns.example.com` served on
the machine `redis.example.com` the following changes need to be made to the data for the `example.com` zone:

* **An `NS` record** for `rkvdns.example.com`:
```
rkvdns.example.com. IN NS redis.example.com.
```
* **An `A` record** for `redis.example.com` (if it doesn't already exist); adjust the address accordingly:
```
redis.example.com. IN A 10.0.1.11
```

### Recursing / caching server

The following instructions are for the _BIND_ nameserver, although analogous options should exist for your nameserver of choice.

Make the following changes in `named.conf`:

* If possible, add `qname-minimization disabled;` to the `options` section. Discuss security and performance implications with your DNS administrator.
* If needed, add a `static-stub` definition for the delegating zone, adjusting the address accordingly. This step is only necessary if the delegating domain is unpublished and can't be determined from the public DNS:
```
zone "example.com" {
    type static-stub;
    server-addresses { 10.0.10.120; };
};
```
The address should be the one for the _delegating server_, NOT the _RKVDNS_ server.

### The RKVDNS server

Adjust the following configuration items for the _RKVDNS_ server:

* `NXDOMAN_FOR_SERVFAIL` set this to `True`
* `ALL_QUERIES_AS_TXT` set this to `False`
* `RKVDNS_FQDN` should be set to the name of the _RKVDNS_ server, `redis.example.com` in our example above.
* `SOA_CONTACT` should be set to the name of the administrative contact, `admin.example.com` in our example above.

## Issues with Caching / Recursing Servers

Congratulations, at this point _RKVDNS_ should be working in your environment. You can minimize the impact of some choices made in DNS
implementations as follows.

* Set `CONFORMANCE` equal to `True`

This interferes with in-band error reporting but minimizes misbehaviors due to caching / recursing resolvers misinterpreting the semantics
of _RKVDNS_ error reporting.

### Excessive query retransmission

You probably have no control over the query retransmission rate. You might want to let your recursive / caching server vendor know
that you want the ability to tune this for better performance in data applications.

#### marshalling

Once a query comes in which is deemed worthy of a data lookup, any other queries which come in which would result in the same
data lookup are _marshalled_ together and all of the queries are answered once the (single) data lookup completes. There is a
five second window for this behavior and it is always active.

In the case of excessive retransmissions this means that only a single data lookup is performed, even though multiple responses
will be individually prepared from the data and sent.

It also mitigates the "thundering herd" phenomenon, where if something is suddenly interesting it will tend to be asked about from
multiple sources simultaneously. (This case is not addressed by deduplication.)

#### debouncing

* Set `DEBOUNCE` to `True`

Additional queries for the same data _from the same host address_ will be discarded.

### Excessive queries from qname minimization

The only way to eliminate these queries is to disable _qname minimization_ in the recursing server (see above). If you can't disable
_qname minimization_ you should definitely set `CONFORMANCE = True`.

### Excessive queries / stale values generally

TTL values set and returned by _RKVDNS_ can be greater or less than those set on the underlying keys in the _Redis_ database. Longer
TTL values will result in the recursing server caching the data for longer and less queries; shorter TTLs will have the opposite effect.

Some applications depend on the TTL being within a certain range. For an example, see [rkvdns_examples/totalizers](https://github.com/m3047/rkvdns_examples/tree/main/totalizers)
