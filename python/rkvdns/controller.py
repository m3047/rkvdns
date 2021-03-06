#!/usr/bin/python3
# Copyright (c) 2022 by Fred Morris Tacoma WA
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

import logging
import traceback
import asyncio

import dns.rdatatype as rdtype

from . import io

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None

class Controller(object):
    """Responsible for logical handling of requests.
    
    It drains the pending_queue and processes the requests. It is responsible
    for:
    
    * Damage containment and response to malformed requests (or responses from Redis).
    
    * Orchestrating queries to Redis
    
    * Composing responses from Redis into DNS responses.
    """
    
    ALLOWED_QUERY_TYPES = {
            rdtype.A, rdtype.AAAA, rdtype.TXT
        }

    def __init__(self, pending_queue, response_queue, redis_io, event_loop, zone, statistics):
        self.pending_queue = pending_queue
        self.response_queue = response_queue
        self.redis_io = redis_io
        self.event_loop = event_loop
        self.zone = [ label.lower().encode() for label in zone.strip().split('.') ]
        if statistics is not None:
            self.pre_redis_stats = statistics.Collector('pre_redis')
            self.redis_stats = statistics.Collector('redis')
            self.write_queue_stats = statistics.Collector('write_queue')
        else:
            self.pre_redis_stats = None
            self.redis_stats = None
            self.write_queue_stats = None
        
        queue_processor = event_loop.create_task(self.process_pending_queue())

        return

    def qtype_not_allowed(self, req, qtype):
        logging.error('FORMERR: Disallowed qtype: {} in: {} from: {}'.format(
                rdtype.to_text(qtype), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr()
        return req
    
    def nxdomain(self, req):
        logging.warning('NXDOMAIN: Key or zone not found in: {} from: {}'.format(
                req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.nxdomain()
        return req
    
    def no_operation(self, req):
        logging.warning('FORMERR: Operation not specified in: {} from: {}'.format(
                req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr()
        return req
                
    def parameter_error(self, req, e):
        logging.error('FORMERR: {} in: {} from: {}'.format(
                repr(e), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.formerr()
        return req

    def query_failure(self, req, e):
        logging.error('SERVFAIL: {} in: {} from: {}'.format(
                repr(e), req.request.question[0].name.to_text(), req.plug.query_address
            ))
        req.servfail()
        return req
    
    def query_success(self, req, query):
        req.noerror(query)
        return req

    async def process_pending_queue(self):
        """If everything looks good, calls io.RedisIO.submit()"""
        while True:
            req = await self.pending_queue.get()
                        
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> process_pending_queue ({})'.format(req.request.id))
                    
            self.pending_queue.task_done()
            
            if self.pre_redis_stats is not None:
                timer = self.pre_redis_stats.start_timer()
            else:
                timer = None
            
            qtype = req.request.question[0].rdtype
            if not req.response_config.all_queries_as_txt and qtype not in self.ALLOWED_QUERY_TYPES:
                await self.response_queue.write( self.qtype_not_allowed(req, qtype) )
                if timer is not None:
                    timer.stop()
                continue
            qlabels = list(req.request.question[0].name.labels)            
            if not qlabels[-1]:
                del qlabels[-1]
            zlen = len(self.zone) * -1

            if self.zone[zlen:] != [ label.lower() for label in qlabels[zlen:] ]:
                await self.response_queue.write( self.nxdomain(req) )
                if timer is not None:
                    timer.stop()
                continue
            if len(qlabels) == len(self.zone):
                await self.response_queue.write( self.no_operation(req) )
                if timer is not None:
                    timer.stop()
                continue
            
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
                await self.response_queue.write( self.query_failure(req, e) )
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
            
        