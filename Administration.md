# Administration

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

### A pretty name

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

This is not the "correct" way to set up or administer a zone, I'm not saying it is. It's just a quick way which
will probably work.

You should be running RPZ on a caching nameserver. You will need to query that nameserver or a nameserver which forwards
to it for this to work.

In all cases below, the records are intended to go into one or more locally administered RPZs. RPZs have a precedence or
application order. Below when we refer to the "first" or "second" RPZ we are referring to the order in which the RPZs are
processed. Oftentimes the first one is called the white or allow list and the second one is called the black or deny list.

### SOA record

___The service DOES NOT support zone transfers.___

You may need an `SOA` record. The following in an RPZ will do the trick:

```
PROXY.REDIS.EXAMPLE.COM. IN SOA  REDIS.EXAMPLE.COM. OPERATOR.EXAMPLE.COM. 1 999999 999999 999999 5
```
`1` is the serial number, and `5` is whatever MIN_TTL is set to. The other three parameters are all pertinent
to zone transfers and should be set to large values.

### In-zone nameservers

The DNS calls in-zone nameservers _in bailiwick_.

```
PROXY.REDIS.EXAMPLE.COM. IN NS   REDIS.EXAMPLE.COM.
```

This is arguably useless if the caching nameserver is also authoritative for `example.com` (the enclosing zone).

### DNS application firewall

#### Blocking an operator

Blocks the `KEYS` operator:

```
*.KEYS.PROXY.REDIS.EXAMPLE.COM. IN CNAME  .
```

#### Allowing a specific query

You need to create two entries for this.

In the first RPZ, create the allow rule:

```
foo.GET.PROXY.REDIS.EXAMPLE.COM. IN CNAME  rpz-passthru.
```

In the second RPZ, create the default deny rule:

```
*.PROXY.REDIS.EXAMPLE.COM  IN CNAME .
```

-------------------

For paid support: fwm.rkvdns.support.f2u@m3047.net
