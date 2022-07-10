Copy `configuration-sample.py` to `configuration.py` and make the necessary changes at the bottom. You may want
to review other settings as well. Setting `LOG_LEVEL = logging.INFO` may be useful while getting started.

Once you've installed `dnspython` and the (python) `redis` package and created `configuration.py` you should be able
to run `./agent.py` from this directory.

**TIP: Not seeing any data, but you know the key is defined? The default query type for most DNS tools is the `A` record type.
try specifying `TXT` in your query, for example `dig foo.get.redis.example.com. TXT`.**
