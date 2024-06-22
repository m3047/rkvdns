#!/usr/bin/python3
# Copyright (c) 2019-2023 by Fred Morris Tacoma WA
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""DNS Proxy for Redis

This service provides DNS proxying for Redis.

    agent.py {interface} {redis-db}
    
Supported Operations
--------------------

Access is read-only. Not all operations are supported; supported operations are
listed below. FQDN semantics follow the general DNS least.scope.to.most.scope
paradigm.

GET -- Value Associated with the Key

    <key>.get.<zone>
   
    Get the value for the key "foo":
    
    foo.get.redis.example.com

HGET -- Value Associated with a Hash Key

    <hkey>.<key>.hget.<zone>
    
    Get the value associated with "bar" in the "foo" hash:
    
    bar.foo.hkey.redis.example.com
    
HKEYS -- Keys in a Hash

    <key>.hkeys.<zone>
    
    Get the keys in the "foo" hash:
    
    foo.hkeys.redis.example.com
    
HLEN -- Number of Elements in a Hash

    <key>.hlen.<zone>
    
    Get the number of elements in the "foo" hash:
    
    foo.hlen.redis.example.com
    
KEYS -- Keys Matching a Pattern

    <pattern>.keys.<zone>
    
    Get the keys starting with "foo":
    
    foo*.keys.redis.example.com
    
KLEN -- Number of Keys Matching a Pattern

    <pattern>.klen.<zone>
    
    Get the count of keys starting with "foo":
    
    foo*.klen.redis.example.com

    Get the count of keys ending with "foo":
    
    *foo.klen.redis.example.com

KPLEN -- Number of Keys Matching a Prefix

    <prefix>.klen.<zone>
    
    Get the count of keys starting with "foo":
    
    foo.kplen.redis.example.com
    
    Internally the prefix is appended with '*', so "foo" becomes "foo*". This is
    for people using e.g. Ignition, where the implementation of gethostbyname() is so
    paranoid it disallows anything which doesn't look like a hostname.

LINDEX -- Nth Element of a List

    <index>.<key>.lindex.<zone>
    
    Get the 4th element of the "foo" list:
    
    3.foo.lindex.redis.example.com
    
    An out of bounds index results in no data.
    
LLEN -- Number of Elements in a List

    <key>.llen.<zone>
    
    Get the length of the "foo" list:
    
    foo.llen.redis.example.com
    
LRANGE -- A Range of Elements of a List

    <range>.<key>.lrange.<zone>
    
    Get all elements of the "foo" list:
    
    0:.foo.lrange.redis.example.com
    
    or alternatively:
    
    0:-1.foo.lrange.redis.example.com
    
    Get the first 4 elements of the "foo" list:
    
    :4.foo.lrange.redis.example.com
    
    Ranges have semantics which should be familiar to both python and
    redis users.
    
    Multiple elements result in multiple rdata occurrences (like nameservers).
    
    Out of bounds indices can result in partial or no data.
    
    No ordering of returned results is guaranteed.
    
SCARD -- Number of Elements in a Set

    <key>.scard.<zone>
    
    Get the number of elements in the "foo" set:
    
    foo.scard.redis.example.com
    
SMEMBERS -- Members of a Set

    <key>.smembers.<zone>
    
    Get the members of the set "foo":
    
    foo.smembers.redis.example.com
    
    Multiple elements result in multiple rdata occurrences (like nameservers).
    
    No ordering of returned results is guaranteed.
    
Introspection
-------------

CONFIG -- Report Configuration Information

    config.<zone>
    
Record Not Found Semantics
--------------------------

These semantics are affected by the setting of CONFORMANCE. If True, then the
return is always either NoAnswer if the sequence of labels could plausibly be part
of a valid query, or NXDOMAIN if not. The exception to this is key not found, where
a valid query is demonstrably conveyed yet fails to return a result; this always
returns NXDOMAIN.

If CONFORMANCE is False, the following applies. In all cases the semantics are
{<parameter>.}<key>.<operation>.<zone>.

Operation Not Found:

    Returns FORMERR
    
Key Not Found:

    Returns NXDOMAIN except in the case of KEYS or SMEMBERS which return
    an empty result.
    
Value Not Found:

    Returns an empty result. This can be the result from KEYS or SMEMBERS as
    well as LINDEX or LRANGE with an out-of-bounds index.
    
Empty key value:

    Returns FORMERR
    
Invalid parameter:

    LINDEX and LRANGE expect an integer or an integer range respectively.
    Returns FORMERR.
    
NS and SOA Record Synthesis
---------------------------

As documented in the sample configuration file, NS and SOA records will be
synthesized if RKVDNS_FQDN (nameserver name) and SOA_CONTACT (zone admin
email) are specified. The records are constructed from the various configuration
values as follows:

    <ZONE> <DEFAULT_TTL> IN NS <RKVDNS_FQDN>

    <ZONE> <DEFAULT_TTL> IN SOA <RKVDNS_FQDN> <SOA_CONTACT> 1 <DEFAULT_TTL> <DEFAULT_TTL> 86400 <MIN_TTL>

DNS-Imposed Limitations
-----------------------

The nature of the DNS imposes a number of performance as well as hard
limitations.

THE UDP LIMIT: DNS defaults to UDP as a transport, and only falls back to
TCP when the response won't fit in a datagram. UDP avoids the setup as well as
teardown associated with TCP as well as the retry. You should not fragment
UDP. You should not alter MAX_UDP_PAYLOAD without specific knowledge of your
network.

If you keep the values you query for below MAX_UDP_PAYLOAD, your queries will be
faster from Redis and also faster if you put this behind a caching nameserver
(which you should).

THE HARD LIMIT: DNS imposes a hard limit on the size of a DNS message of 64K.
A value slightly smaller than this is set with MAX_TCP_PAYLOAD, and again you
shouldn't modify this value without specific knowledge.

This limit is a particularly important consideration with the LRANGE and
SMEMBERS operations. If this hard limit is exceeded then SERVFAIL will be
returned and an error will be logged. You can change this behavior by setting
RETURN_PARTIAL_TCP=True and a warning will be logged.

THE HARD VALUE LIMIT: DNS imposes a hard limit on values of 255 octets (bytes).
This value is set with MAX_VALUE_PAYLOAD and you shouldn't change it.

This limit is a consideration for all operations. If this hard limit is exceeded
then SERVFAIL will be returned and an error will be logged. You can change this
behavior by setting RETURN_PARTIAL_VALUE=True and a warning will be logged.

TTLs
----

TTLs for the DNS records are taken from Redis where possible. If no TTL
has been set in Redis then DEFAULT_TTL is used.

To force a particular TTL for DNS records, set MIN_TTL, MAX_TTL and
DEFAULT_TTL to the same value (in seconds).

Case Folding
------------

The DNS by default treats uppercase and lowercase characters equivalently, or
in other words "example.com" is the same as "eXAmPle.COm". Case may not be
preserved in all circumstances. This may affect Redis queries.

CASE_FOLDING allows you to control what happens. There are four options:

  None          Nothing happens, we accept it verbatim.
  upper         Forces keys and patterns to uppercase.
  lower         Forces them to lowercase.
  escape        The first three octets of the key or pattern define escapes
                which apply to the following octet when they occur.

Debouncing and Marshalling
--------------------------

Mitigations are in place for bad behavior by DNS clients combined with slow Redis
queries. The precipitating issue in general is slow Redis queries.

Because of so-called "happy eyeballs" recursing resolvers may display a tendency
of rapidly repeating the same query while awaiting an answer. (Some may mint new
query ids when doing this, but I digress.) Setting DEBOUNCE=True in the configuration
will suppress multiple identical queries from the same source address ignoring
query ids.

The other bad behavior is what is commonly called the "thundering herd". It is quite
possible that although stuff tends not to get queried ("write caching" is discussed
elsewhere) when stuff does get queried it may get queried a lot. A caching resolver
is intended to mitigate this by serving repeated queries from its cache. But what can
also happen is applications query multiple caching resolvers looking for the answer,
and all of those queries end up at RKVDNS looking for the authoritative source.
Marshalling is the process of matching DNS queries to Redis queries, and answering
multiple DNS queries from the same Redis query when possible. Marshalling is always
enabled.
"""

import sysconfig

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

import sys
import logging
import traceback

import asyncio
from redis.exceptions import ConnectionError

import dns.rdatatype as rdatatype
import dns.rcode as rcode

from rkvdns.statistics import StatisticsFactory
import rkvdns.io as io
import rkvdns.controller
from rkvdns.controller import Controller
from rkvdns import FOLDERS

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

# Set this to a print func to enable it.
PRINT_COROUTINE_ENTRY_EXIT = None

io.PRINT_COROUTINE_ENTRY_EXIT = rkvdns.controller.PRINT_COROUTINE_ENTRY_EXIT = PRINT_COROUTINE_ENTRY_EXIT

# Similar to the foregoing, but always set to something valid.
STATISTICS_PRINTER = logging.info

MAX_PENDING = 50

MAX_UDP_PAYLOAD = 1200
MAX_TCP_PAYLOAD = 60000
MAX_VALUE_PAYLOAD = 255
RETURN_PARTIAL_TCP = False
RETURN_PARTIAL_VALUE = False
NXDOMAIN_FOR_SERVFAIL = False
    
ALL_QUERIES_AS_TXT = False
CASE_FOLDING = None

MAX_TTL = 3600
DEFAULT_TTL = 30
MIN_TTL = 5

LOG_LEVEL = None
STATS = 3600
QUEUE_DEPTH = None

ENABLE_ERROR_TXT = False
LEAK_SEMAPHORE_IF_EXCEPTION = False

RKVDNS_FQDN = None
SOA_CONTACT = None

# This is the Redis key which we use for orchestrating tests.
CONTROL_KEY = None

# Turns on host-based debouncing if True.
DEBOUNCE = False

# Maximal conformance at the expense of error reporting if True
CONFORMANCE = False

# Time limit on TCP connections with no activity. Defaults to rkvdns.io.dns.TcpConnection.DEFAULT_TIMEOUT
TCP_TIMEOUT = None

if __name__ == "__main__":
    from configuration import *
else:
    INTERFACE = '127.0.0.1'
    REDIS_SERVER = '127.0.0.1'
    
    ZONE = 'redis.example.com'

ZONE = [ label.lower().encode() for label in ZONE.strip('.').split('.') ]

# These two are not encoded because they're fed to rdata.from_text() and it
# doesn't seem to like byte strings.
if RKVDNS_FQDN is not None:
    RKVDNS_FQDN = [ label.lower() for label in RKVDNS_FQDN.strip('.').split('.') ]
if SOA_CONTACT is not None:
    SOA_CONTACT = [ label.lower() for label in SOA_CONTACT.strip('.').split('.') ]

if LOG_LEVEL is not None:
    logging.basicConfig(level=LOG_LEVEL)
    
def format_statistics(stat):
    if 'depth' in stat:
        return '{}: emin={:.4f} emax={:.4f} e1={:.4f} e10={:.4f} e60={:.4f} dmin={} dmax={} d1={:.4f} d10={:.4f} d60={:.4f} nmin={} nmax={} n1={:.4f} n10={:.4f} n60={:.4f}'.format(
                stat['name'],
                stat['elapsed']['minimum'], stat['elapsed']['maximum'], stat['elapsed']['one'], stat['elapsed']['ten'], stat['elapsed']['sixty'],
                stat['depth']['minimum'], stat['depth']['maximum'], stat['depth']['one'], stat['depth']['ten'], stat['depth']['sixty'],
                stat['n_per_sec']['minimum'], stat['n_per_sec']['maximum'], stat['n_per_sec']['one'], stat['n_per_sec']['ten'], stat['n_per_sec']['sixty'])
    else:
        return '{}: emin={:.4f} emax={:.4f} e1={:.4f} e10={:.4f} e60={:.4f} nmin={} nmax={} n1={:.4f} n10={:.4f} n60={:.4f}'.format(
                stat['name'],
                stat['elapsed']['minimum'], stat['elapsed']['maximum'], stat['elapsed']['one'], stat['elapsed']['ten'], stat['elapsed']['sixty'],
                stat['n_per_sec']['minimum'], stat['n_per_sec']['maximum'], stat['n_per_sec']['one'], stat['n_per_sec']['ten'], stat['n_per_sec']['sixty'])

async def statistics_report(statistics, frequency):
    """The statistics report.
    
    You will need to look through code to determine exactly what is being measured.
    
    The general overview of what is measured is documented in rkvdns.statistics.
    
    Most statistics measure a "point in the process". The three statistics udp_drop,
    udp and tcp represent the "end to end" disposition of individual requests so
    things like queue depth don't make sense.
    """
    logging.info('statistics_report started')
    while True:
        await asyncio.sleep(frequency)
        for stat in sorted(statistics.stats(), key=lambda x:x['name']):
            STATISTICS_PRINTER(format_statistics(stat))
    return

async def queue_depth_report(pending, response):
    """The queue depth report.
    
    To operate "backpressure", three queues are managed (along with the
    semaphore enclosing the redis query operation):
    
    * Pending   A single pending queue is utilized for both TCP and UDP requests.
    * TcpPlug   The TCP write queue.
    * UdpPlug   The Udp write queue.
    """
    logging.info('queue_depth_report started')
    while True:
        await asyncio.sleep(QUEUE_DEPTH)
        STATISTICS_PRINTER(
            '    '.join(
                ((  '{}:{}'.format(k, q.qsize())
                    for k,q in sorted(
                        kv for kv in ([('Pending',pending)] + list(response.queues))
                    )
                ))
            )
        )
    return

async def close_tasks(tasks):
    all_tasks = asyncio.gather(*tasks)
    all_tasks.cancel()
    try:
        await all_tasks
    except (CancelledError, ConnectionError):
        pass
    return

def resolve_args():
    """Resolve command line arguments."""
    if len(sys.argv) <= 1:
        interface = INTERFACE
    else:
        interface = sys.argv[1]
    if len(sys.argv) <= 2:
        redis_server = REDIS_SERVER
    else:
        redis_server = sys.argv[2]
        
    return (interface, redis_server)

def main():
    interface, redis_server = resolve_args()
    
    if CASE_FOLDING not in FOLDERS:
        logging.fatal('Unrecognized value for CASE_FOLDING: "{}"'.format(CASE_FOLDING))
        sys.exit(1)
    
    logging.info('Redis Proxy DNS Agent starting. listening: {}  redis: {}'.format(interface, redis_server))

    event_loop = asyncio.new_event_loop()
    asyncio.set_event_loop( event_loop )

    if STATS:
        statistics = StatisticsFactory()
        statistics_routine = event_loop.create_task(statistics_report(statistics, STATS))
    else:
        statistics = None
    
    # This structure is passed by reference to every io.Request object.
    response_config = io.ResponseConfig(
                        max_udp_payload     = MAX_UDP_PAYLOAD,
                        max_tcp_payload     = MAX_TCP_PAYLOAD,
                        max_value_payload   = MAX_VALUE_PAYLOAD,
                        return_partial_tcp  = RETURN_PARTIAL_TCP,
                        return_partial_value= RETURN_PARTIAL_VALUE,
                        nxdomain_for_servfail=NXDOMAIN_FOR_SERVFAIL,
                        max_ttl             = MAX_TTL,
                        default_ttl         = DEFAULT_TTL,
                        min_ttl             = MIN_TTL,
                        all_queries_as_txt  = ALL_QUERIES_AS_TXT,
                        folder              = FOLDERS[CASE_FOLDING],
                        control_key         = CONTROL_KEY,
                        enable_error_txt    = ENABLE_ERROR_TXT,
                        zone                = ZONE,
                        rkvdns_fqdn         = RKVDNS_FQDN,
                        soa_contact         = SOA_CONTACT,
                        debounce            = DEBOUNCE,
                        conformance         = CONFORMANCE,
                        tcp_timeout         = TCP_TIMEOUT,
                        # These are for test scaffolding, but have no other impact.
                        redis_server        = redis_server,
                        redis_timeout       = 5,
                        incrementing        = None,
                        pending_delay_ms    = None
    )

    pending_queue = asyncio.Queue(MAX_PENDING)
    response_queue = io.DnsResponseQueue(MAX_PENDING, event_loop)

    dns_io = io.DnsIO( interface, event_loop, pending_queue, response_queue, response_config, statistics )
    redis_io = io.RedisIO( redis_server, event_loop, LEAK_SEMAPHORE_IF_EXCEPTION )
    controller = Controller( pending_queue, response_queue, redis_io, event_loop, ZONE, statistics,
                             response_config.control_key, response_config.debounce, response_config.conformance )

    if QUEUE_DEPTH:
        depth_routine = event_loop.create_task( queue_depth_report(pending_queue, response_queue) )
        
    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass

    dns_io.close()
    
    if PYTHON_IS_311:
        tasks = asyncio.all_tasks(event_loop)
    else:
        tasks = asyncio.Task.all_tasks(event_loop)

    if tasks:
        event_loop.run_until_complete(close_tasks(tasks))
    
    event_loop.close()
    
    return

if __name__ == '__main__':
    main()
    
