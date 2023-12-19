The tests read and write data in the configured Redis database. These artifacts are corralled in the key
prefix defined by `CONTROL_KEY`. Tinkering with tests and examining the DNS traffic with _Wireshark_ can prove
enlightening.

### `TestInfrastructure` Tests are Slow

The tests in `end_to_end.TestInfrastructure` can take a (literal) minute to run, during which they're not
doing anything. However what they're doing is waiting for timeouts / timing issues. Be patient; go refill your
beverage.
