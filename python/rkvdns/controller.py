#!/usr/bin/python3
# Copyright (c) 2022-2023 by Fred Morris Tacoma WA
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
"""Control."""

from time import time

import logging
import traceback
import asyncio

import dns.rdatatype as rdtype

from . import io

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None

# Controls the number of seconds over which debouncing occurs.
DEBOUNCING_WINDOW = 5   # seconds

class RequestList(object):
    """Stores a list of requests for the same thing, to be processed the same way.
    
    There can be more than one request to be answered, but the answer is always
    the same.
    """
    TCP = 'tcp'
    UDP = 'udp'
    
    def __init__(self, query, tcp_or_udp):
        self.requests = []
        self.tcp_or_udp = tcp_or_udp
        self.query = query
        self.answer = None
        self.udp_limit = None
        self.tc = False
        self.precalc_ = None
        return
    
    def add_request(self, req):
        self.requests.append(req)
        return
    
    def add_answer(self, req, udp_limit=None, tc=False):
        self.answer = req.response.answer
        self.udp_limit = self.tcp_or_udp == self.UDP and udp_limit or None
        self.tc = tc
        return
    
    def payload_size_precalc(self, req):
        if self.precalc_ is None:
            results = self.query.results()
            if not results or isinstance(results[0], int):
                self.precalc_ = True
            else:
                # As a side effect this actually modifies self.query.result.
                self.precalc_ = req.payload_size_precalc( results )
        return self.precalc_
    
class DictOfRequests(dict):
    """A dictionary of lists of requests.
    
    A unique request in this context is a tuple of (subkey or None, key, operator, qtype,
    'udp'/'tcp').
    
    NOTE: The functional distinction is whether the response is truncated (TC=1),
    but in practice we don't know this until the Redis query completes, and TCP
    is (usually) only tried if a UDP query returns with TC=1. The downside of
    discriminating on TCP/UDP is a requery in the TCP case if UDP was in fact tried
    first, returning TC=1. The Redis query can be expensive, but what has been found
    to be truly expensive in practice is building the DNS answer (blame dnspython)
    from it.
    
    It is possible for an initial UDP request event to arrive with a large enough
    EDNS payload size that the entire payload fits, and a subsequent one to arrive with
    a smaller payload size requiring truncation. In this case, the truncation is
    recomputed and any further subsequent events receive the truncated version. In
    other words, truncation is cumulative and later events receive the smallest acceptable
    answer.
    """
    @staticmethod
    def request_key(req, query):
        """Returns the dictionary key for the specified request."""
        return tuple( query.parameter_list + [ req.qtype, isinstance(req.plug, io.TcpPlug) and RequestList.TCP or RequestList.UDP ] )
        
    def add_request(self, k, req, query=None):
        """Add a request to the appropriate list of requests.
        
        Each distinct query has a separately maintained list.
        
        Returns the RequestList.
        """
        if k not in self:
            if query is None:
                raise RuntimeError('Expected an io.RedisQuery')
            self[k] = RequestList(query, k[-1])
        self[k].add_request(req)
        
        return

class Debouncer(object):
    """Time-bounded duplicate detector."""
    def __init__(self, redis_stats, seconds=DEBOUNCING_WINDOW):
        """Default is to debounce for 5 seconds."""
        self.redis_stats = redis_stats
        self.seconds = seconds
        self.buckets = []
        self.last = int(time())
        return
    
    def find_query(self, k):
        for b in self.buckets:
            if k in b:
                return b[k]
        return None
    
    def reply(self, req, query, submit_query, reply_callback):
        """Prepare a reply.
        
        This may not happen immediately if the Redis query needs to be performed.
        
        Returns a future (or None) to be awaited for disposition of the request.
        """
        now = time()
        if now > self.last:
            while now > self.last:
                self.buckets.insert( 0, DictOfRequests() )
                self.last += 1
            del self.buckets[self.seconds:]

        k = DictOfRequests.request_key( req, query )
        request_list = self.find_query(k)

        # Query has not been seen.
        if not request_list:
            self.buckets[0].add_request(k, req, query)
            tied_requests = self.find_query(k)
            return submit_query( query,
                        self.complete_pending_requests(
                            reply_callback, tied_requests, query, self.redis_stats and self.redis_stats.start_timer() or None
                        ),
                        req.request.id
                    )
        
        # Query is pending.
        if request_list.answer is None:
            for bucket in self.buckets:
                if k in bucket:
                    ignore = bucket.add_request(k, req)
                    return None
            raise KeyError( '{} not found in buckets.'.format(k) )
        
        # Query is ready.
        return reply_callback( req, request_list.query, request_list )

    async def complete_pending_requests( self, reply_callback, tied_requests, query, redis_timer):
        """Complete any pending requests."""

        for req in tied_requests.requests:
            await reply_callback(req, query, tied_requests)

        return
    
class Controller(object):
    """Responsible for logical handling of requests.
    
    It drains the pending_queue and processes the requests. It is responsible
    for:
    
    * Damage containment and response to malformed requests (or responses from Redis).
    
    * Orchestrating queries to Redis
    
    * Composing responses from Redis into DNS responses.
    
    Similarly to Response Rate Limiting, if multiple requests for the same
    (<client-address>, <qname>, <rdata-type>) come in within the (module-level)
    DEBOUNCING_WINDOW window, the additional requests are dropped.
    """
    
    ALLOWED_QUERY_TYPES = {
            rdtype.A, rdtype.AAAA, rdtype.TXT
        }
    
    def __init__(self, pending_queue, response_queue, redis_io, event_loop, zone, statistics, control_key):
        self.pending_queue = pending_queue
        self.response_queue = response_queue
        self.redis_io = redis_io
        self.event_loop = event_loop
        self.zone = zone
        if statistics is not None:
            self.pre_redis_stats = statistics.Collector('pre_redis')
            self.redis_stats = statistics.Collector('redis')
            self.write_queue_stats = statistics.Collector('write_queue')
        else:
            self.pre_redis_stats = None
            self.redis_stats = None
            self.write_queue_stats = None
        # Passed so that the pending queue processor can be smart about whether to
        # interrogate requests for testing shims to be passed on to e.g. the RedisIO processor.
        self.control_key = control_key
        
        self.queue_processor = event_loop.create_task(self.process_pending_queue())

        return

    def qtype_not_allowed(self, req):
        logging.error('FORMERR: Disallowed qtype: {} in: {} from: {}'.format(
                rdtype.to_text(req.qtype), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr('Disallowed qtype: {}'.format(rdtype.to_text(req.qtype)))
        return req
    
    def nxdomain(self, req):
        logging.warning('NXDOMAIN: Key or zone not found in: {} from: {}'.format(
                req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.nxdomain('Key or zone not found.')
        return req
    
    def no_operation(self, req):
        logging.warning('FORMERR: Operation not specified in: {} from: {}'.format(
                req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr('Operation not specified.')
        return req
    
    def parameter_error(self, req, e):
        logging.error('FORMERR: {} in: {} from: {}'.format(
                repr(e), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr('Parameter error: {}'.format(repr(e)))
        return req

    def query_failure(self, req, e):
        logging.error('SERVFAIL: {} in: {} from: {}'.format(
                repr(e), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.servfail('Query failure: {}'.format(repr(e)))
        return req
    
    def query_success(self, req):
        req.noerror()
        return req

    async def process_pending_queue(self):
        """If everything looks good, calls io.RedisIO.submit()"""
        zoff = len(self.zone) * -1
        debouncer = Debouncer( self.redis_stats )
        while True:
            req = await self.pending_queue.get()
            
            #
            # +++ Test shimming.
            #
            # This is automated, see end_to_end.WithRedis.set_config() and io.Request.patch_for_test()
            if self.control_key:

                if req.response_config.incrementing:
                    incrementing_encoded = req.response_config.incrementing.encode()
                    if (  'incrementing' in self.redis_io.test_shims
                      and self.redis_io.test_shims['incrementing']['k'] != incrementing_encoded
                       ):
                        del self.redis_io.test_shims['incrementing']
                    if 'incrementing' not in self.redis_io.test_shims:
                        self.redis_io.test_shims['incrementing'] = {
                                'k': incrementing_encoded,
                                'v': 0
                            }
                elif 'incrementing' in self.redis_io.test_shims:
                    del self.redis_io.test_shims['incrementing']

                if req.response_config.pending_delay_ms:
                    await asyncio.sleep(req.response_config.pending_delay_ms / 1000)
                    
            # --- Test shimming.
            #

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> process_pending_queue ({})'.format(req.request.id))
                    
            self.pending_queue.task_done()
            
            if self.pre_redis_stats is not None:
                timer = self.pre_redis_stats.start_timer()
            else:
                timer = None
            
            # Correct zone?
            # NOTE: This is the point at which the Request.request promise is finalized.
            if self.zone[zoff:] != [ label.lower() for label in req.qlabels[zoff:] ]:
                await self.response_queue.write( self.nxdomain(req) )
                if timer is not None:
                    timer.stop()
                continue

            # Just the naked zone, no redis query?
            if len(req.qlabels) == len(self.zone):
                if   req.qtype == rdtype.SOA:
                    req = req.soa()
                elif req.qtype == rdtype.NS:
                    req = req.ns()
                else:
                    req = self.no_operation(req)

                await self.response_queue.write( req )
                if timer is not None:
                    timer.stop()
                continue

            # This is a redis query.
            if not req.response_config.all_queries_as_txt and req.qtype not in self.ALLOWED_QUERY_TYPES:
                await self.response_queue.write( self.qtype_not_allowed(req) )
                if timer is not None:
                    timer.stop()
                continue
                        
            # Ok, looks good.
            try:
                query = io.RedisQuery(req.qlabels[:zoff], req.response_config.folder).finalize()
            except io.RedisError as e:
                await self.response_queue.write( self.parameter_error(req, e) )
                if timer is not None:
                    timer.stop()
                continue

            # One of three things happens here, two of them result in dispositions.
            # 1) The query hasn't been seen before and self.redis_io.submit() is called to perform
            #    the redis query, carrying debouncer.complete_pending_requests() to complete any
            #    identical requests by calling self.redis_callback()
            # 2) No answer has been built yet, in which case this request becomes a pending request.
            # 3) An answer has been built and self.redis_callback() is called directly.
            disposition = debouncer.reply( req, query, self.redis_io.submit, self.redis_callback )
            if disposition:
                await disposition

            if timer is not None:
                timer.stop()
            
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< process_pending_queue ({})'.format(req.request.id))
        
        # Should never exit.
        raise RuntimeError("Control loop should never exit.")

    async def redis_callback(self, req, query, tied_requests):
        """Reply to DNS request.
        
        Originally this was called on Redis query completion, but now it is called
        to complete requests. The subtle difference is that multiple requests can now
        be completed from the same query and finishing is done by Debouncer.complete_pending_requests().
        """
        
        try:
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> redis_callback ({})'.format(req.request.id))

            if self.write_queue_stats is not None:
                timer = self.write_queue_stats.start_timer()
            else:
                timer = None

            if   query.exception is not None:
                await self.response_queue.write( self.query_failure(req, query.exception) )
            elif query.result is None:
                await self.response_queue.write( self.nxdomain(req) )
            else:
                if not tied_requests.payload_size_precalc( req ):
                    logging.warning('Impossibly large payload for: {} from: {}'.format(
                        req.request.question[0].name.to_text(), req.plug.query_address
                    ))
                    if req.response_config.nxdomain_for_servfail:
                        await self.response_queue.write( req.nxdomain( 'Impossibly large payload.' ) )
                    else:
                        await self.response_queue.write( req.servfail( 'Impossibly large payload.' ) )
                else:
                    # Fabricate rrsets. This is actually deferred until to_wire() is called after the
                    # request is dequeued in order to be written.
                    self.query_success( req )
                    await self.response_queue.write( req, tied_requests )
            
            if timer is not None:
                timer.stop()

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< redis_callback ({})'.format(req.request.id))
        except Exception as e:
            logging.fatal('An exception occurred in Controller.redis_callback(). Traceback follows.')
            logging.fatal(traceback.format_exc())
        return
    
