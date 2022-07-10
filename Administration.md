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

### SOA record

### In-zone nameservers

### DNS application firewall

