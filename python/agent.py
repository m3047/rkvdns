#!/usr/bin/python3
# Copyright (c) 2019-2022 by Fred Morris Tacoma WA
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
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
    
KEYS -- Keys Matching a Pattern

    <pattern>.keys.<zone>
    
    Get the keys starting with "foo":
    
    foo*.keys.redis.example.com
    
LINDEX -- Nth Element of a List

    <index>.<key>.lindex.<zone>
    
    Get the 4th element of the "foo" list:
    
    3.foo.lindex.redis.example.com
    
    An out of bounds index results in no data.
    
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
    
SMEMBERS -- Members of a Set

    <key>.smembers.<zone>
    
    Get the members of the set "foo":
    
    foo.smembers.redis.example.com
    
    Multiple elements result in multiple rdata occurrences (like nameservers).
    
    No ordering of returned results is guaranteed.
    
Record Not Found Semantics
--------------------------

In all cases the semantics are {<parameter>.}<key>.<operation>.<zone>.

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
"""
import sys
import logging
import traceback

import asyncio
from concurrent.futures import CancelledError
from redis.exceptions import ConnectionError

import dns.rdatatype as rdatatype
import dns.rcode as rcode

from rkvdns.statistics import StatisticsFactory
import rkvdns.io as io
import rkvdns.controller
from rkvdns.controller import Controller
from rkvdns import FOLDERS

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
    
ALL_QUERIES_AS_TXT = False
CASE_FOLDING = None

MAX_TTL = 3600
DEFAULT_TTL = 30
MIN_TTL = 5

LOG_LEVEL = None
STATS = 3600
QUEUE_DEPTH = None

# This is the Redis key which we use for orchestrating tests.
CONTROL_KEY = None

#CONSOLE = None

if __name__ == "__main__":
    from configuration import *
else:
    INTERFACE = '127.0.0.1'
    REDIS_SERVER = '127.0.0.1'
    
    ZONE = 'redis.example.com'
    
#if CONSOLE:
    #import rkvdns.console as console

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

    event_loop = asyncio.get_event_loop()

    if STATS:
        statistics = StatisticsFactory()
        asyncio.run_coroutine_threadsafe(statistics_report(statistics, STATS), event_loop)
    else:
        statistics = None
    
    # This structure is passed by reference to every io.Request object.
    response_config = io.ResponseConfig(
                        max_udp_payload     = MAX_UDP_PAYLOAD,
                        max_tcp_payload     = MAX_TCP_PAYLOAD,
                        max_value_payload   = MAX_VALUE_PAYLOAD,
                        return_partial_tcp  = RETURN_PARTIAL_TCP,
                        return_partial_value= RETURN_PARTIAL_VALUE,
                        max_ttl             = MAX_TTL,
                        default_ttl         = DEFAULT_TTL,
                        min_ttl             = MIN_TTL,
                        all_queries_as_txt  = ALL_QUERIES_AS_TXT,
                        folder              = FOLDERS[CASE_FOLDING],
                        control_key         = CONTROL_KEY,
                        # These are for test scaffolding, but have no other impact.
                        redis_server        = redis_server,
                        redis_timeout       = 5
    )

    pending_queue = asyncio.Queue(MAX_PENDING, loop=event_loop)
    response_queue = io.DnsResponseQueue(MAX_PENDING, event_loop)

    dns_io = io.DnsIO( interface, event_loop, pending_queue, response_queue, response_config, statistics )
    redis_io = io.RedisIO( redis_server, event_loop )
    controller = Controller( pending_queue, response_queue, redis_io, event_loop, ZONE, statistics )

    if QUEUE_DEPTH:
        asyncio.run_coroutine_threadsafe( queue_depth_report(pending_queue, response_queue), event_loop)
        
    #if CONSOLE:
        #console_ctxt = console.Context()
        #console_service = event_loop.run_until_complete(
                #asyncio.start_server(
                    #console_ctxt.handle_requests,
                    #CONSOLE['host'], CONSOLE['port'], 
                    #loop=event_loop, limit=MAX_READ_SIZE
                #)
            #)

    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass

    dns_io.close()
    
    tasks = asyncio.Task.all_tasks(event_loop)
    if tasks:
        event_loop.run_until_complete(close_tasks(tasks))
    
    event_loop.close()
    
    return

if __name__ == '__main__':
    main()
    
