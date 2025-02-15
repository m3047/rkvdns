# The `SHARDS` Command

There is no `SHARDS` command in _Redis_ (although they have my blessing to implement it). This software is released as open source under the _AGPL_ and
my philosophy is to encourage "shift left" (change what you write to _Redis_) and "shift right" (postprocess what you retrieve from _Redis_), but this
comports well with the use cases which often come up in my stories of what I do with data. So, here it is.

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

##### mulltiple wildcards

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
