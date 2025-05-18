# The `SHARDS` and `SHGET` Commands

There is no `SHARDS` command in _Redis_ (although they have my blessing to implement it).
This software (RKVDNS) is released as open source under the _AGPL_ and
my philosophy is to encourage "shift left" (change what you write to _Redis_) and "shift right" (postprocess what you retrieve from _Redis_), but this
comports well with the use cases which often come up in my stories of what I do with data. So, here it is. -- Fred Morris, February 2025

`SHARDS` performs a `KEYS` operation internally, but only returns the unique wildcarded parts of the query string. A query string for `SHARDS` can be the
very same, wildcarded, query string you'd use with `KEYS`:

    <pattern>.shards.<zone>

### Patterns and wildcards

Compared to `KEYS`, only asterisk ("*") wildcarding is supported, but this comes in two flavors.

##### "*" wildcarding with capture

Given you had a pattern `foo*bar` and you passed it to `KEYS`, it would return all keys starting with `foo` and ending with `bar`. If you pass this
same pattern to `SHARDS` it will return everything that was _between_ `foo` and `bar` for each of the keys.

You can have more than one wildcard in a pattern, and in this case each wildcarded match group is preserved as a separate string in the DNS `TXT` record:
the pattern `foo*bar*` returns `TXT` records containing what occurred between `foo` and `bar`, and whatever occurred after `bar`.

##### "**" wildcarding without capture

A double asterisk is passed to the underlying `KEYS` command as a single asterisk. It behaves as an asterisk wildcard but no capture is done:
the pattern `foo**bar*` returns `TXT` records containing only what occurred after `bar`.

### Examples

##### `KEYS` example

This demonstrates what the `KEYS` operator returns for the wildcard pattern.

```
# dig '10\.0\.0\.224;*;flow.keys.redis.athena.m3047' txt +short | head -5
"10.0.0.224;10.0.0.220;53;flow"
"10.0.0.224;10.0.0.220;123;flow"
"10.0.0.224;140.82.114.26;443;flow"
"10.0.0.224;224.0.0.251;5353;flow"
"10.0.0.224;140.82.116.3;443;flow"
```

##### `SHARDS` example

This is the same pattern passed to the `SHARDS` operator.

```
# dig '10\.0\.0\.224;*;flow.shards.redis.athena.m3047' txt +short | head -5
"224.0.0.251;5353"
"140.82.114.25;443"
"140.82.116.3;443"
"140.82.116.4;22"
"34.149.100.209;443"
```

##### multiple wildcards

Here we modify the pattern to capture the address and port separately.

```
# dig '10\.0\.0\.224;*;*;flow.shards.redis.athena.m3047' txt +short | head -5
"34.149.100.209" "443"
"10.0.0.220" "123"
"10.0.0.220" "22"
"140.82.116.3" "443"
"10.0.0.220" "53"
```

##### only the address or port

We can use the double asterisk to capture either the address or port but not both.

```
# dig '10\.0\.0\.224;*;**;flow.shards.redis.athena.m3047' txt +short | head -5
"140.82.114.25"
"10.0.0.253"
"224.0.0.251"
"10.0.0.220"
"140.82.116.3"
# dig '10\.0\.0\.224;**;*;flow.shards.redis.athena.m3047' txt +short | head -5
"5353"
"443"
"22"
"53"
"123"
```

### Intermezzo: Breaking Things

Before I go over the `SHGET` command in detail I want to play with some edge cases, because after I understand the basic concepts
I oftentimes find them illuminating before trying for full comprehension.

##### a bad idea: `KEYS '*'`

It's a bad idea, but it works:

```
# dig '*.keys.redis.sophia.m3047' txt +short | head -5
"syslog_tags;kactivitymanagerd;sophia;1747583669"
"web_client;10.0.0.118,200;sophia;1747546909"
"web_page;swebok-v4.pdf,200;sophia;1747527657"
"syslog_tags;systemd;sophia;1747540467"
"health"
```

The `KLEN` (not found in _Redis_, an _RKVDNS_ confection) is not much better: just as abusive to your _Redis_ instance, a little
kinder to _the DNS_:

```
# dig '*.klen.redis.sophia.m3047' txt +short
"92"
```

##### pointless: `KEYS` with no `'*'`

This also works, but what's the point? I guess you can use it to test for the presence of a key when you don't know
what type of key it is:

```
# dig 'health.keys.redis.sophia.m3047' txt +short
"health"
# dig 'health.get.redis.sophia.m3047' txt +short
"redis.sophia.m3047."
```

For completeness, there are no other keys in this _Redis_ instance which start with `health`:

```
# dig 'health*.keys.redis.sophia.m3047' txt +short
"health"
```

##### what happens with `SHARDS`?

Here is the same initial edge case we demonstrated with `KEYS` repeated with `SHARDS`:

```
# dig '*.shards.redis.sophia.m3047' txt +short | head -5
"syslog_tags;/usr/sbin/cron;mnemosyne;1747588280"
"syslog_tags;rkvdns-agent;sophia;1747562068"
"syslog_tags;dbus-daemon;sophia;1747562068"
"syslog_tags;org_kde_powerdevil;sophia;1747540467"
"syslog_tags;rkvdns-agent;sophia;1747540467"
```

But `SHARDS 'health'` returns an error. With `CONFORMANCE = True` you'll get `NXDOMAIN`, otherwise `FORMERR`, and
in either case the error is logged:

```
# dig 'health.shards.redis.sophia.m3047' txt | head -n6 | tail -n2
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 33181
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
# journalctl -u rkvdns-agent | tail -n1
May 18 14:01:15 sophia rkvdns-agent[25531]: ERROR:root:NXDOMAIN: RedisSyntaxError() in: health.shards.redis.sophia.m3047. from: 10.0.0.220
```

A clue: the non-capturing `'**'` also returns an error:

```
# dig '**.shards.redis.sophia.m3047' txt | head -n6 | tail -n2
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 63503
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
```

___IN A NUTSHELL, `SHARDS` requires something to capture.___

Alrighty then:

```
# dig 'health*.shards.redis.sophia.m3047' txt +short
""
```

Did you see that coming? The `health` key exists, and that's it: the shard is empty.

### `SHGET`: Returning the values for multiple `GET`-able keys

`SHGET` combines a `KEYS` query with (multiple) `GET` queries to retrieve the underlying values:

```
# dig 'health*.shget.redis.sophia.m3047' txt +short
"" "redis.sophia.m3047."
```

So that gives us the empty shard, plus the value of the (only) `health` key. You know where this is going,
am I right?

```
# dig '*.shget.redis.sophia.m3047' txt +short | head -5
"web_page;text.gif,200;sophia;1747527657" "2"
"syslog_tags;access_log;sophia;1747562068" "6"
"syslog_tags;dbus-daemon;sophia;1747562068" "12"
"syslog_tags;/usr/sbin/cron;mnemosyne;1747501876" "48"
"syslog_tags;systemd-tmpfiles;sophia;1747518424" "9"
```

**NOTE:** Because we scanned the entire _Redis_ datastore, this example does _NOT_ work if any of the keys
in the database is something other than string-valued. Instead, it will return `SERVFAIL` and you'll get a bunch of log messages.
Choose your wildcards carefully.

___`SHGET` only works if all of the retrieved keys are string-valued.___

##### some better, more useful examples

With all of the foregoing there should be no surprises here:

```
# dig 'syslog_tags;*.shget.redis.sophia.m3047' txt +short | head -5
"kwin_x11;sophia;1747518424" "34"
"kactivitymanagerd;sophia;1747583669" "99"
"access_log;sophia;1747562068" "6"
"plasmashell;sophia;1747562068" "6"
"dolphin;sophia;1747583669" "7"
```

If we have multiple shard pieces, they're listed before the value(s):

```
# dig 'syslog_tags;*;*;*.shget.redis.sophia.m3047' txt +short | head -5
"dolphin" "sophia" "1747518424" "4"
"kactivitymanagerd" "sophia" "1747583669" "99"
"cron" "sophia" "1747540467" "13"
"rkvdns-agent" "sophia" "1747540467" "48"
"rkvdns-agent" "sophia" "1747562068" "48"
# dig 'syslog_tags;systemd;*;*.shget.redis.sophia.m3047' txt +short
"sophia" "1747583669" "66"
"sophia" "1747540467" "65"
"sophia" "1747562068" "58"
"sophia" "1747518424" "109"
"mnemosyne" "1747523476" "2"
```

But we can also rollup values:

```
# dig 'syslog_tags;systemd;*;**.shget.redis.sophia.m3047' txt +short
"sophia" "58" "66" "109" "65"
"mnemosyne" "2"
```
