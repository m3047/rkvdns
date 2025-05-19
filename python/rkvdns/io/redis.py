#!/usr/bin/python3
# Copyright (c) 2022-2025 by Fred Morris Tacoma WA
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
"""I/O Operations for Redis.

DEBUG_FOLDING
-------------

Setting this to e.g. print or logging.info will print out the case folding
being applied. It is very verbose, but can be handy if queries are NX and you
just can't undertand why.
"""

import sys
import logging
import traceback
from math import floor

from time import time

import asyncio
from concurrent.futures import ThreadPoolExecutor

import re
import redis

from ipaddress import IPv4Address, IPv6Address
from random import random

from .. import FunctionResult, FOLDERS
from ..statistics import StatisticsCollector, UndeterminedStatisticsCollector

# Start/end of coroutines. Delayed import happens in RedisIO.__init__()
#from . import PRINT_COROUTINE_ENTRY_EXIT

# Prints the type of folding and before / after.
DEBUG_FOLDING = None

#################################################################################
# REDIS QUERY
#################################################################################

class DictOfLists(dict):
    def append(self, k, v):
        if k not in self:
            self[k] = []
        self[k].append(v)
        return

class ShardDecoder(object):
    """Handles conversion and processing of shards for RedisShardsQuery.
    
    Shards are wildcarded parts of the keyspec passed to keys(). If there
    is more than one wildcarded part of the keyspec and you don't want to
    return a part, specify "**" as the wildcard rather than "*". It will still
    be passed to Redis as "*", but the resulting part of returned keys will
    not be returned as part of the shard.
    """
    
    WILDCARD_SEPARATOR = re.compile(b'(\*+)')
    
    def __init__(self, key):
        
        self.key_ = [
                part[0] == b'*' and part[:2] or part
                for part in
                self.WILDCARD_SEPARATOR.split(key)
                if part
            ]

        parts = []
        for part in self.key_:
            if   part == b'**':
                parts.append(b'.*')
            elif part == b'*':
                parts.append(b'(.*)')
            else:
                parts.append( part )
        self.shards = re.compile(b''.join(parts))

        return
    
    def valid(self):
        """There has to be at least one returnable shard defined."""
        return b'*' in self.key_
    
    @property
    def key(self):
        """The actual keyspec passed to Redis."""
        return b''.join(
                part[0] == b'*' and b'*' or part
                for part in self.key_
            )
    
    def sharded(self, value):
        """Extract and return sharded values as tuples."""
        matched = self.shards.fullmatch(value)
        if matched is None:
            return None
        return matched.groups()

class RedisError(Exception):
    pass

class RedisOperandError(RedisError):
    """The operand was not one of the anticipated ones."""
    pass

class RedisParameterError(RedisError):
    """Something wrong with the supplied labels."""
    pass

class RedisSyntaxError(RedisError):
    """Something is wrong with one of the parameters."""
    pass

class RedisBaseQuery(object):
    """All redis queries are subclasses of this."""
    
    MULTIVALUED = False
    HAS_TTL = True
    INTEGER_VALUE = re.compile(b'-?\d+')
    MAX_PARAMS = 3  # This should not be changed when subclassed!
    
    def __init__(self, query, folder):
        if len(self.PARAMETERS) != len(query):
            raise RedisParameterError()
        for param, value in zip(self.PARAMETERS, query):
            if not len(value):
                raise RedisParameterError()
            object.__setattr__(self, param, value)
        # parameter_list is used for building the dictionary key for looking up active queries.
        self.parameter_list = query
        if len(query) < self.MAX_PARAMS:    # Always either 2 or 3
            self.parameter_list.insert(0, None)
        # The parameter to the left of the operand is always a key or pattern.
        self.folder = folder
        self.fold(-2)
        self.validate()
        return
    
    def fold(self, i):
        attr = self.PARAMETERS[i]
        if DEBUG_FOLDING:
            DEBUG_FOLDING('folding: {}\nbefore: {}\nafter: {}'.format(attr, getattr(self, attr), self.folder(getattr(self, attr))))
        setattr(self, attr, self.folder(getattr(self, attr)) )
        return
    
    def validate(self):
        """Default is a no-op.
        
        Should raise an exception if invalid. Basic check is to ensure
        that all parameters are nonempty although that check is done in
        __init__()
        """
        return
    
    def finalize(self):
        """Last chance to kick an Exception before queueing up. (FLUENT)
        
        The Exception should be subclassed from io.RedisError.
        """
        return self
    
    def store_result(self, result, exception):
        """Store the redis query result or exception. (FLUENT)"""
        self.result = result
        self.exception = exception
        return self
    
    def resolve_ttl(self, conn):
        """Query for TTL if appropriate. (FLUENT)"""
        if not self.HAS_TTL:
            self.ttl = None
            return
        self.ttl = conn.ttl(self.key)
        return self
    
    def results(self):
        """A something with the results which can be iterated over."""
        if self.result is None:
            return []
        if not self.MULTIVALUED:
            return [self.result]
        return self.result
    
class RedisGetQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )
    
    def query(self, conn):
        """Returns value or None."""
        return conn.get(self.key)

class RedisHGetQuery(RedisBaseQuery):
    PARAMETERS = ( 'hkey', 'key', 'operand' )
    
    def __init__(self, *args):
        RedisBaseQuery.__init__(self, *args)
        self.fold(-3) # hkey
        return
    
    def query(self, conn):
        """Returns value or None."""
        return conn.hget(self.key, self.hkey)

class RedisHKeysQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )
    MULTIVALUED = True

    def query(self, conn):
        """Returns a list; may be empty."""
        return conn.hkeys(self.key)

class RedisHLenQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )

    def query(self, conn):
        """Returns the number of fields in the hash."""
        return conn.hlen(self.key)
    
class RedisKeysQuery(RedisBaseQuery):
    PARAMETERS = ( 'pattern', 'operand' )
    MULTIVALUED = True
    HAS_TTL = False

    def query(self, conn):
        """Returns a list; may be empty."""
        return conn.keys(self.pattern)
        
class RedisLIndexQuery(RedisBaseQuery):
    PARAMETERS = ( 'index', 'key', 'operand' )
    
    def validate(self):
        if not self.INTEGER_VALUE.fullmatch(self.index):
            raise RedisSyntaxError()
        return
    
    def query(self, conn):
        """Returns value or ???."""
        return conn.lindex(self.key, self.index)

class RedisLengthOfKeysQuery(RedisBaseQuery):
    PARAMETERS = ( 'pattern', 'operand' )
    HAS_TTL = False

    def query(self, conn):
        """Returns the number of keys matching the pattern."""
        return len(conn.keys(self.pattern))
    
class RedisLengthOfKeysPrefixQuery(RedisBaseQuery):
    PARAMETERS = ( 'pattern', 'operand' )
    HAS_TTL = False

    def query(self, conn):
        """Returns the number of keys matching the pattern.
        
        This is for the Ignition SCADA people.
        """
        return len(conn.keys(self.pattern + b'*'))

class RedisLLenQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )

    def query(self, conn):
        """Returns the length of the list."""
        return conn.llen(self.key)

class RedisLRangeQuery(RedisBaseQuery):
    PARAMETERS = ( 'range', 'key', 'operand' )
    MULTIVALUED = True
    
    def validate(self):
        irange = self.range.split(b':')
        if len(irange) != 2:
                raise RedisSyntaxError()
        for v in irange:
            if len(v) and not self.INTEGER_VALUE.fullmatch(v):
                raise RedisSyntaxError()
        return

    def query(self, conn):
        """Returns a list; may be empty."""
        irange = self.range.split(b':')
        if not irange[0]:
            irange[0] = 0
        if not irange[1]:
            irange[1] = -1
        return conn.lrange(self.key, *[ int(bounds) for bounds in irange ] )

class RedisSCardQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )

    def query(self, conn):
        """Returns the cardinality of a set."""
        return conn.scard(self.key)

class RedisShardedQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )
    MULTIVALUED = True
    HAS_TTL = False
    
    def finalize(self):
        """Sharded queries must contain a valid shard."""
        self.sharder = ShardDecoder( self.key )
        if not self.sharder.valid():
            raise RedisSyntaxError()
        return self
    
class RedisShardsQuery(RedisShardedQuery):
    
    def query(self, conn):
        shards = set()
        for k in conn.keys( self.sharder.key ):
            sharded = self.sharder.sharded( k )
            if not sharded:
                continue
            shards.add( sharded )
            
        return list( shards )
    
class RedisShardsGetQuery(RedisShardedQuery):

    def query(self, conn):
        shards = DictOfLists()        
        for k in conn.keys( self.sharder.key ):
            sharded = self.sharder.sharded( k )
            if not sharded:
                continue
            v = conn.get( k )
            if v is None:
                continue
            shards.append( sharded, v )
        
        return [ k + tuple( v ) for k,v in shards.items() ]

class RedisSMembersQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )
    MULTIVALUED = True

    def query(self, conn):
        """Returns a list; may be empty."""
        return list(conn.smembers(self.key))
        
REDIS_QUERY_TYPES = {
        b'get'     : RedisGetQuery,
        b'hget'    : RedisHGetQuery,
        b'hkeys'   : RedisHKeysQuery,
        b'keys'    : RedisKeysQuery,
        b'klen'    : RedisLengthOfKeysQuery,
        b'kplen'   : RedisLengthOfKeysPrefixQuery,
        b'hlen'    : RedisHLenQuery,
        b'lindex'  : RedisLIndexQuery,
        b'llen'    : RedisLLenQuery,
        b'lrange'  : RedisLRangeQuery,
        b'scard'   : RedisSCardQuery,
        b'shards'  : RedisShardsQuery,
        b'shget'   : RedisShardsGetQuery,
        b'smembers': RedisSMembersQuery
    }

def RedisQuery(query, *args):
    """Returns the correct query class or None."""
    query[-1] = query[-1].lower()
    if query[-1] not in REDIS_QUERY_TYPES:
        raise RedisOperandError()
    return REDIS_QUERY_TYPES[query[-1]](query, *args)

#################################################################################
# REDIS I/O
#################################################################################

class RedisIO(object):
    """Encapsulates I/O with Redis.
    
    We actually manage it as a thread pool, although the default setting is
    a single worker.
    """
    WORKERS = 1
    CONNECT_TIMEOUT = 5

    def __init__(self, server, loop, leak_semaphore_if_exception):
        """We allow a backlog of one extra query."""
        from . import PRINT_COROUTINE_ENTRY_EXIT
        globals()['PRINT_COROUTINE_ENTRY_EXIT'] = PRINT_COROUTINE_ENTRY_EXIT
        
        self.event_loop = loop
        self.leak_semaphore_if_exception = leak_semaphore_if_exception
        self.semaphore = asyncio.Semaphore( self.WORKERS+1 )
        self.pool = ThreadPoolExecutor(self.WORKERS)
        self.redis = redis.client.Redis(server, decode_responses=False,
                                        socket_connect_timeout=self.CONNECT_TIMEOUT
                                       )
        self.finishers = set()
        self.test_shims = {}
        return
    
    def redis_job(self, query, callback):
        """The actual job run in the thread pool.
        
        INTENTIONAL SEMAPHORE LEAK if LEAK_SEMAPHORE_IF_EXCEPTION = True
        
        If True we only release the semaphore if there was no exception kicked,
        and so repeated exceptions will result in a deadlock. This is intentional
        to make the situation self-limiting in the case of adversarial input and
        should be revisited.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> redis_job')
            
        try:
            exc = result = None
            #
            # NOTE: If a key value is specified as the value of the "incrementing" override
            #       in a test, that value can be incremented and returned here as the (apparent)
            #       result of a GET operation but it's never actually read / written to Redis.
            if (  'incrementing' in self.test_shims
              and isinstance(query, RedisGetQuery)
              and query.key == self.test_shims['incrementing']['k']
               ):
                self.test_shims['incrementing']['v'] += 1
                result = self.test_shims['incrementing']['v']
                query.ttl = None
            else:
                result = query.query(self.redis)
                query.resolve_ttl(self.redis)
        except redis.exceptions.ConnectionError as e:
            logging.error('redis.exceptions.ConnectionError: {}'.format(e))
            exc = e
        except Exception as e:
            logging.warning('{}:\n{}'.format(e, traceback.format_exc()))
            exc = e
        query.store_result( result, exc )

        promise = []
        finisher = asyncio.run_coroutine_threadsafe(
                        self.finish_job(exc, result, callback, promise), self.event_loop
                    )
        if not promise:
            promise.append(finisher)
            self.finishers.add(finisher)

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< redis_job')
        return
    
    async def finish_job(self, exc, result, callback, promise):
        """Part II of redis_job() runs as a coroutine
        
        ...rather than in the thread pool.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> finish_job')

        await callback

        if exc is None or not self.leak_semaphore_if_exception:
            self.semaphore.release()
        if promise:
            self.finishers.remove(promise[0])
        else:
            promise.append( None )

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< finish_job')
        return
    
    async def submit(self, query, callback, request_id):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> submit ({})'.format(request_id))

        await self.semaphore.acquire()
        self.event_loop.run_in_executor(self.pool, self.redis_job, query, callback)

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< submit ({})'.format(request_id))
        return
    
    
    
