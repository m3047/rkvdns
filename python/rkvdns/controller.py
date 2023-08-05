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

class Debouncer(object):
    """Time-bounded duplicate detector."""
    def __init__(self, seconds=DEBOUNCING_WINDOW):
        """Default is to debounce for 5 seconds."""
        self.seconds = seconds
        self.buckets = []
        self.last = int(time())
        return
    
    def is_duplicate(self, k):
        """If the key has been seen in the last 5 seconds, return True."""
        now = int(time())
        if now > self.last:
            while now > self.last:
                self.buckets.insert(0,set())
                self.last += 1
            del self.buckets[self.seconds:]
        for bucket in self.buckets:
            if k in bucket:
                return True
        self.buckets[0].add(k)
        return False
    
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
    
    def __init__(self, pending_queue, response_queue, redis_io, event_loop, zone, statistics):
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
        
        self.queue_processor = event_loop.create_task(self.process_pending_queue())

        return

    def qtype_not_allowed(self, req, qtype):
        logging.error('FORMERR: Disallowed qtype: {} in: {} from: {}'.format(
                rdtype.to_text(qtype), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr('Disallowed qtype: {}'.format(rdtype.to_text(qtype)))
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
    
    def query_success(self, req, query):
        req.noerror(query)
        return req

    async def process_pending_queue(self):
        """If everything looks good, calls io.RedisIO.submit()"""
        debouncer = Debouncer()
        while True:
            req = await self.pending_queue.get()
                        
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> process_pending_queue ({})'.format(req.request.id))
                    
            self.pending_queue.task_done()
            
            if self.pre_redis_stats is not None:
                timer = self.pre_redis_stats.start_timer()
            else:
                timer = None
            
            # NOTE: This is the point at which the Request.request promise is finalized.
            qlabels = list(req.request.question[0].name.labels)            
            if not qlabels[-1]:
                del qlabels[-1]
            zlen = len(self.zone) * -1

            # Correct zone?
            if self.zone[zlen:] != [ label.lower() for label in qlabels[zlen:] ]:
                await self.response_queue.write( self.nxdomain(req) )
                if timer is not None:
                    timer.stop()
                continue

            qtype = req.request.question[0].rdtype

            # Just the naked zone, no redis query?
            if len(qlabels) == len(self.zone):
                if   qtype == rdtype.SOA:
                    req = req.soa()
                elif qtype == rdtype.NS:
                    req = req.ns()
                else:
                    req = self.no_operation(req)

                await self.response_queue.write( req )
                if timer is not None:
                    timer.stop()
                continue

            # This is a redis query.
            if not req.response_config.all_queries_as_txt and qtype not in self.ALLOWED_QUERY_TYPES:
                await self.response_queue.write( self.qtype_not_allowed(req, qtype) )
                if timer is not None:
                    timer.stop()
                continue
            
            # Debouncing.
            if isinstance(req.plug, io.UdpPlug):
                if debouncer.is_duplicate((
                        req.plug.query_address,
                        req.request.question[0].name.to_text().lower(),
                        req.request.question[0].rdtype
                    )):
                    # Drop it on the floor.
                    if timer is not None:
                        timer.stop()
                        req.timer.stop('debounce')
                    continue
            
            # Ok, looks good.
            try:
                query = io.RedisQuery(qlabels[:zlen], req.response_config.folder).finalize()
            except io.RedisError as e:
                await self.response_queue.write( self.parameter_error(req, e) )
                if timer is not None:
                    timer.stop()
                continue

            query.id = req.request.id
            await self.redis_io.submit(query, self.redis_callback(req, query, self.redis_stats and self.redis_stats.start_timer() or None))
            
            if timer is not None:
                timer.stop()
            
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< process_pending_queue ({})'.format(req.request.id))
        
        # Should never exit.
        raise RuntimeError("Control loop should never exit.")

    async def redis_callback(self, req, query, redis_timer):
        """Completion callback from io.RedisIO.submit()"""
        try:
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> redis_callback ({})'.format(req.request.id))

            if redis_timer is not None:
                redis_timer.stop()
            if self.write_queue_stats is not None:
                timer = self.write_queue_stats.start_timer()
            else:
                timer = None

            if   query.exception is not None:
                await self.response_queue.write( self.query_failure(req, query.exception) )
            elif query.result is None:
                await self.response_queue.write( self.nxdomain(req) )
            else:
            # Fabricate rrsets
                await self.response_queue.write( self.query_success( req, query ) )
            
            if timer is not None:
                timer.stop()

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< redis_callback ({})'.format(req.request.id))
        except Exception as e:
            logging.fatal('An exception occurred in Controller.redis_callback(). Traceback on STDOUT.')
            traceback.print_exc()
        return
            
        