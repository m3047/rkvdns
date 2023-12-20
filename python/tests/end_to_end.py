#!/usr/bin/python3
# Copyright (c) 2022 Fred Morris Tacoma WA USA
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

"""Running These Tests

These tests require a working Redis instance and a working configuration.py.

Enabling Testing in configuration.py with CONTROL_KEY
-----------------------------------------------------

CONTROL_KEY defines a key prefix which will be used for all keys inserted
into the redis database by the test suite.

Normally IT SHOULD NOT BE DEFINED except when running the test suite, because
it causes the service to read the CONTROL_KEY hash for every request.
"""

import sys
import unittest
import redis
import math
from dns.resolver import Resolver
import dns.rcode as rcode
from dns.resolver import NXDOMAIN, NoNameservers, NoAnswer      # Exceptions
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rdtypes.ANY.TXT import TXT
import dns.flags
import dns.query, dns.message
import dns.rdatatype as rdtype
import re
import concurrent.futures
from random import random
import time
import threading

if '..' not in sys.path:
    sys.path.insert(0,'..')

import configuration as config

class CountingDict(dict):
    def inc(self, k):
        if k not in self:
            self[k] = 0
        self[k] += 1
        return

# This is the default config which gets set in the CONTROL_KEY redis hash.
#
# NOTE: The implementation of io.Request.patch_for_test() doesn't handle floats gracefully.
#       Don't try to pass floats for ints, and for that matter don't try to pass floats.
DEFAULT_CONFIG = dict(
        max_pending = 50,

        max_udp_payload = 1200,
        max_tcp_payload = 60000,
        max_value_payload = 255,
        return_partial_tcp = 'False',
        return_partial_value = 'False',
            
        all_queries_as_txt = 'False',
        case_folding = 'None',

        max_ttl = 3600,
        default_ttl = 30,
        min_ttl = 5        
    )

class WithRedis(unittest.TestCase):
    REDIS = True
    RESOLVER = True
    THREADING = False
    
    def setUp(self):
        if self.REDIS:
            self.redis = redis.client.Redis( config.REDIS_SERVER, decode_responses=True,
                                            socket_connect_timeout=5
                                        )

        self.zone = config.ZONE.rstrip() + '.'
        if self.RESOLVER:
            self.resolver = self.setUpResolver()
            
        if self.THREADING:
            self.locks = dict( query=threading.Lock(), resp=threading.Lock() )

        return
    
    def setUpResolver(self):
        resolver = Resolver(configure=False)
        resolver.domain = self.zone
        resolver.nameservers = [config.INTERFACE]
        return resolver
    
    def set_config(self, **kwargs):
        temp_config = DEFAULT_CONFIG.copy()
        temp_config.update(kwargs)
        for k,v in temp_config.items():
            self.redis.hset(config.CONTROL_KEY, k, v)
        return
    
    def tearDown(self):
        """Remove test entries from Redis.
        
        NOTE: We do our best to delete all upper cased and lower cased variants
              as well!
        """
        if self.REDIS:
            for key in (config.CONTROL_KEY, config.CONTROL_KEY.lower(), config.CONTROL_KEY.upper()):
                keys = self.redis.keys(key + '*')
                if keys:
                    self.redis.delete(*keys)
        return

class TestOptions(WithRedis):
    """Tests the effects of various configuration settings."""
    
    def test_all_queries_txt(self):
        self.set_config(all_queries_as_txt='True')
        key = config.CONTROL_KEY + '_all_queries_txt'
        self.redis.set(key,'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A', raise_on_no_answer=False)
        self.assertTrue(isinstance(resp.response.answer[0][0], TXT))
        self.assertEqual(resp.response.answer[0][0].strings[0], b'1.3.3.7')
        return
    
    def test_default_ttl(self):
        self.set_config()

        key = config.CONTROL_KEY + '_default_ttl_1'
        self.redis.set(key,'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')

        self.assertEqual(resp.response.answer[0].ttl, DEFAULT_CONFIG['default_ttl'])

        key = config.CONTROL_KEY + '_default_ttl_2'
        self.redis.set(key,'1.3.3.7')
        self.redis.expire(key, 42)
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')

        self.assertEqual(resp.response.answer[0].ttl, 42)

        return
    
    def test_min_ttl(self):
        self.set_config(min_ttl=20)
        key = config.CONTROL_KEY + '_min_ttl'
        self.redis.set(key,'1.3.3.7')
        self.redis.expire(key, 13)
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertEqual(resp.response.answer[0].ttl, 20)
        return
    
    def test_max_ttl(self):
        self.set_config(max_ttl=60)
        key = config.CONTROL_KEY + '_max_ttl'
        self.redis.set(key,'1.3.3.7')
        self.redis.expire(key, 1440)
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertEqual(resp.response.answer[0].ttl, 60)
        return
    
    def test_fold_lower(self):
        self.set_config(case_folding='lower')
        key = config.CONTROL_KEY + '_foLD_lOWer'
        self.redis.set(key.lower(),'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertEqual(resp.response.answer[0][0].to_text(), '1.3.3.7')
        return
        
    def test_fold_upper(self):
        self.set_config(case_folding='upper')
        key = config.CONTROL_KEY + '_foLD_UpPeR'
        self.redis.set(key.upper(),'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertEqual(resp.response.answer[0][0].to_text(), '1.3.3.7')
        return

    def test_fold_escape(self):
        self.set_config(case_folding='escape')
        key = config.CONTROL_KEY + '_foLD_eScApe'
        self.redis.set(key,'1.3.3.7')
        key = '\.+-' + config.CONTROL_KEY + '\._-F-O\.LD_\.e+s-c+ape'
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertEqual(resp.response.answer[0][0].to_text(), '1.3.3.7')
        return

class TestQueries(WithRedis):
    """Tests the different types of supported queries."""

    def test_nx_zone(self):
        self.set_config()
        with self.assertRaises(NXDOMAIN):
            resp = self.resolver.query('foo.bar.','TXT')
        return

    def test_no_operator(self):
        self.set_config()
        with self.assertRaises(NoNameservers):
            resp = self.resolver.query(self.zone,'TXT')
        return
    
    def test_bad_operator(self):
        self.set_config()
        with self.assertRaises(NoNameservers):
            resp = self.resolver.query('foo.'+self.zone,'TXT')
        return

    def test_bad_operator_as_txt(self):
        ASSERTS = { 
            rdtype.CNAME: lambda rr: self.assertTrue( re.match('\d+[.]error[.]', rr.to_text().lower()) ),
            rdtype.TXT:   lambda rr: self.assertTrue( rr.to_text().strip('"').lower().startswith('parameter error: redisoperanderror') )
        }
        self.set_config(enable_error_txt='True')
        resp = self.resolver.query('bar.'+self.zone,'TXT')
        for rrset in resp.response.answer:
            ASSERTS[rrset.rdtype](rrset[0])
        return

    def test_bald_operator(self):
        self.set_config()
        with self.assertRaises(NoNameservers):
            resp = self.resolver.query('get.'+self.zone,'TXT')
        return

    def test_nx_key(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_nx_key'
        with self.assertRaises(NXDOMAIN):
            resp = self.resolver.query(key + '.get.' + self.zone,'TXT')
        return
    
    def test_get(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_get'
        self.redis.set(key, b'42')
        # We slip a test for case insensitivity of the operator in here...
        resp = self.resolver.query(key + '.gEt.' + self.zone, 'TXT')
        self.assertEqual(resp.response.answer[0][0].strings[0], b'42')
        return
    
    def test_hget_nx(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_hget'
        self.redis.hset(key, b'foo', 33)
        self.redis.hset(key, b'bar', 44)
        with self.assertRaises(NXDOMAIN):
            resp = self.resolver.query('baz.' + key + '.hget.' + self.zone, 'TXT')
        return

    def test_hget(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_hget'
        self.redis.hset(key, b'foo', 33)
        self.redis.hset(key, b'bar', 44)
        resp = self.resolver.query('bar.' + key + '.hget.' + self.zone, 'TXT')
        self.assertEqual(resp.response.answer[0][0].strings[0], b'44')
        return
    
    def test_hkeys(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_hkeys'
        self.redis.hset(key, b'foo', 33)
        self.redis.hset(key, b'bar', 44)
        resp = self.resolver.query(key + '.hkeys.' + self.zone, 'TXT')
        all_keys = [ rr.strings[0] for rr in resp.response.answer[0] ]
        self.assertEqual(sorted(all_keys), [b'bar',b'foo'])
        return
    
    def test_lindex(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_lindex'
        self.redis.lpush(key, b'first')
        self.redis.lpush(key, b'second')
        self.redis.lpush(key, b'third')
        resp = self.resolver.query('1.' + key +'.lindex.' + self.zone, 'TXT')
        self.assertEqual(b'second', resp.response.answer[0][0].strings[0])
        return

    def test_lrange(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_lrange'
        self.redis.lpush(key, b'first')
        self.redis.lpush(key, b'second')
        self.redis.lpush(key, b'third')
        resp = self.resolver.query(':-2.' + key +'.lrange.' + self.zone, 'TXT')
        self.assertEqual([b'second', b'third'], sorted(( rr.strings[0] for rr in resp.response.answer[0] )) )
        return
    
    def test_smembers(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_smembers'
        self.redis.sadd(key, b'foo')
        self.redis.sadd(key, b'bar')
        self.redis.sadd(key, b'baz')
        resp = self.resolver.query(key +'.smembers.' + self.zone, 'TXT')
        all_keys = [ rr.strings[0] for rr in resp.response.answer[0] ]
        self.assertEqual(sorted(all_keys), [b'bar', b'baz', b'foo'])
        return
    
    def test_a(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_a'
        self.redis.set(key,'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '1.3.3.7')
        return

    def test_aaaa(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_aaaa'
        self.redis.set(key,'feed:babe::13:37')
        resp = self.resolver.query(key + '.get.' + self.zone, 'AAAA')
        rr = resp.response.answer[0][0]
        self.assertTrue(isinstance(rr, AAAA))
        self.assertEqual(rr.to_text(), 'feed:babe::13:37')
        return

    def test_tcp(self):
        self.set_config()
        key = config.CONTROL_KEY + '_test_tcp'
        self.redis.set(key,'1.3.3.7')
        resp = self.resolver.query(key + '.get.' + self.zone, 'A', tcp=True)
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '1.3.3.7')
        return
    
    def test_truncate_udp(self):
        self.set_config()
        # Because the maximum length of any given rvalue is 255, we have to
        # iterate records to get there. DNS doesn't like duplicate records so
        # we need to mind that too.
        key = config.CONTROL_KEY + '_truncate_udp'
        total = 0
        i = b'A'
        while total <= DEFAULT_CONFIG['max_udp_payload'] + 1:
            self.redis.lpush(key, i * 200)
            i = chr(ord(i)+1)
            total += 200
        # We can't use the dnspython Resolver for this because it will automagically
        # retry with TCP.
        query = dns.message.make_query( ':.' + key + '.lrange.' + self.zone, 'TXT',
                                        use_edns=True, payload=DEFAULT_CONFIG['max_udp_payload']
                                    )
        resp = dns.query.udp(query, config.INTERFACE)
        self.assertTrue( resp.flags & dns.flags.TC != 0)

        max_recs = math.floor(DEFAULT_CONFIG['max_udp_payload'] / 200)
        self.assertTrue( len(resp.answer[0]) > 0 )
        self.assertTrue(len(resp.answer[0]) <= max_recs)

        return
    
    def test_wrong_type(self):
        key = config.CONTROL_KEY + '_wrong_type'
        self.redis.lpush(key, 'A'*200)
        with self.assertRaises(NoNameservers):
            resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        return
    
    def test_tcp_too_large(self):
        self.set_config(max_tcp_payload=3000)
        key = config.CONTROL_KEY + '_tcp_large'
        total = 0
        i = b'A'
        while total <= 3000 + 1:
            self.redis.lpush(key, i * 200)
            i = chr(ord(i)+1)
            total += 200
        with self.assertRaises(NoNameservers):
            resp = self.resolver.query( ':.' + key + '.lrange.' + self.zone, 'TXT', tcp=True)
        return
        
    def test_tcp_too_large_as_txt(self):
        self.set_config(max_tcp_payload=3000, enable_error_txt='True')
        key = config.CONTROL_KEY + '_tcp_large_as_txt'
        total = 0
        i = b'A'
        while total <= 3000 + 1:
            self.redis.lpush(key, i * 200)
            i = chr(ord(i)+1)
            total += 200
        resp = self.resolver.query( ':.' + key + '.lrange.' + self.zone, 'TXT', tcp=True)
        for rrset in resp.response.answer:
            self.assertEqual(len(rrset), 1)
        return

    def test_int_a(self):
        self.set_config()
        key = config.CONTROL_KEY + '_int_a'
        self.redis.incr(key)
        resp = self.resolver.query(key + '.get.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '0.0.0.1')
        return
    
    def test_hlen(self):
        self.set_config()
        key = config.CONTROL_KEY + '_hlen'
        self.redis.hset(key, b'foo', 33)
        self.redis.hset(key, b'bar', 44)
        resp = self.resolver.query(key + '.hlen.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '0.0.0.2')
        return

    def test_hlen_txt(self):
        self.set_config()
        key = config.CONTROL_KEY + '_hlen_txt'
        self.redis.hset(key, b'foo', 33)
        self.redis.hset(key, b'bar', 44)
        resp = self.resolver.query(key + '.hlen.' + self.zone, 'TXT')
        self.assertTrue(isinstance(resp.response.answer[0][0], TXT))
        self.assertEqual(resp.response.answer[0][0].strings[0], b'2')
        return

    def test_klen(self):
        self.set_config()
        key = config.CONTROL_KEY + '_klen_'
        self.redis.incr(key + 'foo')
        self.redis.incr(key + 'bar')
        self.redis.incr(key + 'baz')
        resp = self.resolver.query(key + '*.klen.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '0.0.0.3')
        return
    
    def test_klen_txt(self):
        self.set_config()
        key = config.CONTROL_KEY + '_klen_txt_'
        self.redis.incr(key + 'foo')
        self.redis.incr(key + 'bar')
        self.redis.incr(key + 'baz')
        resp = self.resolver.query(key + '*.klen.' + self.zone, 'TXT')
        self.assertTrue(isinstance(resp.response.answer[0][0], TXT))
        self.assertEqual(resp.response.answer[0][0].strings[0], b'3')
        return

    def test_llen(self):
        self.set_config()
        key = config.CONTROL_KEY + '_llen_'
        self.redis.lpush(key, b'first')
        self.redis.lpush(key, b'second')
        self.redis.lpush(key, b'third')
        resp = self.resolver.query(key + '.llen.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '0.0.0.3')
        return
    
    def test_scard(self):
        self.set_config()
        key = config.CONTROL_KEY + '_scard_'
        self.redis.sadd(key, b'foo')
        self.redis.sadd(key, b'bar')
        self.redis.sadd(key, b'baz')
        self.redis.sadd(key, b'zeep')
        resp = self.resolver.query(key + '.scard.' + self.zone, 'A')
        self.assertTrue(isinstance(resp.response.answer[0][0], A))
        self.assertEqual(resp.response.answer[0][0].to_text(), '0.0.0.4')
        return

class TestInfrastructure(WithRedis):
    """Tests infrastructure, things which aren't knobs or dials.
    
    Examples would be debouncing (dropping duplicate queries) and marshalling
    (answering several duplicate queries with the same result).
    
    These tests may not do what either you or I expect them to do.
    
    NOTE: Each one of these tests can be expected to take HOW_LONG_IS_LONG_IN_SECONDS
          to complete.
    """
    HOW_LONG_IS_LONG_IN_SECONDS = 14
    PENDING_QUEUE_DELAY = 1.5
    NUMBER_OF_QUERIES = int(HOW_LONG_IS_LONG_IN_SECONDS / PENDING_QUEUE_DELAY)
    
    INCREMENTING = 'incrementing'
    
    RESOLVER = False
    THREADING = True
    
    def issuingThread(self, id, timeout=None):
        with self.locks['query']:
            query = query = dns.message.make_query( id + '.get.' + self.zone, 'TXT' )
        with self.locks['resp']:
            try:
                resp = dns.query.udp(query, config.INTERFACE, timeout=timeout)
            except:
                resp = None
        return resp
    
    def test_marshalling_fast_fast(self):
        """Fast issue, fast response.
        
        Multiple queries in short order should not result in individual query issues to Redis.
        
        Expected: 1 Redis query used for all queries.
        """
        id = self.INCREMENTING+'{:04d}'.format( int( random() * 10000 ) )
        self.set_config(incrementing=id)

        threads = set()
        results = CountingDict()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for n in range(self.NUMBER_OF_QUERIES):
                threads.add( executor.submit( self.issuingThread, id ) )
            for thread in concurrent.futures.as_completed( threads ):
                resp = thread.result()
                results.inc( resp.answer[0][0].to_text() )
        self.assertEqual( len(results), 1 )
        self.assertEqual( results.popitem()[1], self.NUMBER_OF_QUERIES )
        return
    
    def test_debouncing(self):
        """Modified version of test_marshalling_fast_fast.
        
        Multiple queries in short order should not result in individual responses to querants.
        
        Expected: 1 query responded to.
        """
        id = self.INCREMENTING+'{:04d}'.format( int( random() * 10000 ) )
        self.set_config(incrementing=id, debounce='True')

        threads = set()
        results = CountingDict()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for n in range(self.NUMBER_OF_QUERIES):
                threads.add( executor.submit( self.issuingThread, id, 0.1 ) )
            for thread in concurrent.futures.as_completed( threads ):
                resp = thread.result()
                if resp is not None:
                    results.inc( resp.answer[0][0].to_text() )
        self.assertEqual( len(results), 1 )
        self.assertEqual( results.popitem()[1], 1 )
        return    

    def test_marshalling_fast_slow(self):
        """Fast issue, slow response.
        
        This takes HOW_LONG_IS_LONG_IN_SECONDS to run.

        Expected: 3 flights, total of 9 queries
        """
        id = self.INCREMENTING+'{:04d}'.format( int( random() * 10000 ) )
        self.set_config(incrementing=id, pending_delay_ms=int(self.PENDING_QUEUE_DELAY * 1000))

        threads = set()
        results = CountingDict()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for n in range(self.NUMBER_OF_QUERIES):
                threads.add( executor.submit( self.issuingThread, id ) )
            for thread in concurrent.futures.as_completed( threads ):
                resp = thread.result()
                results.inc( resp.answer[0][0].to_text() )
        self.assertEqual( len(results), 3 )
        self.assertEqual( sum(results.values()), self.NUMBER_OF_QUERIES )
        return

    def test_marshalling_slow_fast(self):
        """slow issue, fast response.
        
        This takes HOW_LONG_IS_LONG_IN_SECONDS to run.

        Expected: 3 flights, total of 9 queries
        """
        id = self.INCREMENTING+'{:04d}'.format( int( random() * 10000 ) )
        self.set_config(incrementing=id)

        results = CountingDict()
        for n in range(self.NUMBER_OF_QUERIES):
            resp = self.issuingThread( id )
            results.inc( resp.answer[0][0].to_text() )
            time.sleep(self.PENDING_QUEUE_DELAY)
        self.assertEqual( len(results), 3 )
        self.assertEqual( sum(results.values()), self.NUMBER_OF_QUERIES )
        return

    def test_marshalling_slow_slow(self):
        """slow issue, slow response.
        
        This takes 2 * HOW_LOG_IS_LONG_IN_SECONDS to run.
        
        Expected: more than 3 flights, total of 9 queries
        """
        id = self.INCREMENTING+'{:04d}'.format( int( random() * 10000 ) )
        self.set_config(incrementing=id, pending_delay_ms=int(self.PENDING_QUEUE_DELAY * 1000))
            
        results = CountingDict()
        for n in range(self.NUMBER_OF_QUERIES):
            resp = self.issuingThread( id )
            results.inc( resp.answer[0][0].to_text() )
            time.sleep(self.PENDING_QUEUE_DELAY)
        self.assertTrue( len(results) > 3 )
        self.assertEqual( sum(results.values()), self.NUMBER_OF_QUERIES )
        return

if __name__ == '__main__':
    print('Using control key "{}" at redis {}'.format(config.CONTROL_KEY, config.REDIS_SERVER))
    unittest.main(verbosity=2)
