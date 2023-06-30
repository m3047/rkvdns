Copy `configuration-sample.py` to `configuration.py` and make the necessary changes at the bottom. If _redis_ and _rkvdns_
are both installed on the same node and you plan to test there locally (`localhost`), the only thing you need to change is the `ZONE`.
(Although `proxy.redis.example.com` will work fine in this specific case too.)

You may want
to review other settings as well. Setting `LOG_LEVEL = logging.INFO` may be useful while getting started.

Once you've installed `dnspython` and the (python) `redis` package and created `configuration.py` you should be able
to run `./agent.py` from this directory.

**TIP: Not seeing any data, but you know the key is defined? The default query type for most DNS tools is the `A` record type.
Try specifying `TXT` in your query, for example `dig @127.0.0.1 foo.get.proxy.redis.example.com. TXT`**
