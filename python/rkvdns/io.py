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
"""I/O Operations for both Redis and DNS requests.

DEBUG_FOLDING
-------------

Setting this to e.g. print or logging.info will print out the case folding
being applied. It is very verbose, but can be handy if queries are NX and you
just can't undertand why.

DNS EDNS(0) Policy
------------------

Frags

Notwithstanding RFC 6891, frags are really bad: they got it wrong. Our policy
is that UDP is good, but let's not waste time. You are encouraged not to
advertise or anticipate that UDP frags will occur "in the worst case", and go
right ahead and use TCP if that is a plausible occurrence.

You may not have direct control over this if you've done the right thing and
put a caching DNS server in front of this service, because that server will
negotiate its own payload sizes, but that's the way we feel about it here.


Truncated Responses (TC=1)

When our (conservative) UDP payload size is exceeded and we send a truncated
response we will try to send as much data as possible along with TC=1. You can
decide whether that's good enough or retry over TCP. Yes, we do support TCP;
we anticipate that certain applications may want to encrypt the traffic and
what's simpler than putting Nginx in front of this to terminate TLS
on port 853? (That's called DoT.)


Advertised EDNS Payload Sizes

This only applies to UDP. We do not send EDNS in TCP replies. This concerns
the conditions which trigger TC=1 in a UDP reply.

If a (UDP) query does not advertise EDNS we assume a payload size of 512
octets (bytes). No EDNS response is returned.

Our payload size is capped conservatively at 1200 (MAX_UDP_PAYLOAD) octets
by default. Our size calculation is crappy, so it's possible that the payload
we actually return in a UDP packet will exceed this (but not by much)!

We will return the smaller of the requested payload size or the value of
MAX_UDP_PAYLOAD with our EDNS response.
"""

import sys
import logging
import traceback
from math import floor

import asyncio
from concurrent.futures import ThreadPoolExecutor

import re

import dns.message
import dns.rdatatype as rdtype
import dns.rcode as rcode
from dns.rdataset import Rdataset
import dns.rdataclass as rdcls
import dns.rdata as rdata
import dns.rrset as rrset
from dns.rdtypes.ANY.TXT import TXT
import dns.flags
from dns.exception import TooBig

import redis

from ipaddress import IPv4Address, IPv6Address

from . import FunctionResult, FOLDERS
from .statistics import StatisticsCollector, UndeterminedStatisticsCollector

# Start/end of coroutines.
PRINT_COROUTINE_ENTRY_EXIT = None

# Prints the type of folding and before / after.
DEBUG_FOLDING = None

#################################################################################
# DNS I/O PLUGINS
#################################################################################

class DnsPlug(object):
    """Base DNS I/O plugin.
    
    Common elements which are not specific to the particular I/O modality.
    """
    pass

class UdpPlug(DnsPlug):
    
    def __init__(self, address, transport):
        """Address in this case encapsulates the remote address+port."""
        self.address = address
        self.transport = transport
        return
    
    @property
    def query_address(self):
        return self.address[0]
        
    async def write(self, response):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> UdpPlug.write')

        self.transport.sendto( response, self.address )

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< UdpPlug.write')
        return

class TcpPlug(DnsPlug):
    
    def __init__(self, stream):
        self.semaphore = None   # Set prior to calling write()
        self.stream = stream
        return
    
    @property
    def query_address(self):
        return self.stream.writer.get_extra_info('peername')
        
    async def write(self, response):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> TcpPlug.write')

        if self.stream.closed:
            logging.warning('Previously closed channel to {}'.format(self.query_address))
        else:
            try:
                self.stream.writer.write(response)
                await self.stream.writer.drain()
            except Exception as e:
                logging.error('Exception on TCP channel to {}, closing connection. {}'.format(self.query_address, e))
                self.stream.close()
        self.semaphore.release()

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< TcpPlug.write')
        return

DnsPlug.CLASSES = {UdpPlug, TcpPlug}

class TcpConnection(object):
    """The TcpPlug.stream object."""
    
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        return
    
    @property
    def closed(self):
        return self.writer is None
    
    def close(self):
        if self.writer is None:
            return
        self.writer.close()
        self.reader = self.writer = None
        return

#################################################################################
# CONFIGS USED TO CONSTRUCT RESPONSES
#################################################################################
    
class ResponseConfig(object):
    """A container of configuration parameters used when constructing responses.
    
    The following parameters are expected, set from corresponding configuration
    values:

    * max_udp_payload
    * max_tcp_payload
    * max_value_payload
    * return_partial_tcp
    * return_partial_value
    * max_ttl
    * default_ttl
    * min_ttl
    """
    def __init__(self, **kwargs):
        self.config = kwargs
        return
    
    def __getattr__(self, param):
        return self.config[param]
    
    def copy(self):
        return type(self)(**self.config.copy())

#################################################################################
# DNS I/O
#################################################################################

class Request(object):
    """Encapsulates both TCP and UDP DNS requests in a unified model."""
    
    NO_EDNS_PAYLOAD_SIZE = 512
    NO_EDNS_FLAG = -1
    HAS_EDNS_FLAG = 0
    REDIS = None        # For tests / debugging.
    
    STATISTICS_TYPES = ('udp_drop', 'udp', 'tcp')
    REDIS_FIXUP_TEST_KEYS = ('return_partial_tcp', 'return_partial_value', 'all_queries_as_txt', 'case_folding')
    REDIS_FIXUP_VALUES = { 'False':False, 'True':True, 'None':None }
    
    @classmethod
    def statistics_collector(cls, statistics):
        return statistics.Collector(cls.STATISTICS_TYPES, using=UndeterminedStatisticsCollector)

    def __init__(self, plug):
        """Not called directly.
        
        Call the UdpIO and TcpIO constructors.
        """
        self.plug = plug
        # self.udp_limit -- edns_fixup()
        # self.response_config -- with_config()
        return

    @classmethod
    def UdpIO(cls, *args):
        return cls( UdpPlug(*args) )
    
    @classmethod
    def TcpIO(cls, *args):
        return cls( TcpPlug(*args) )
    
    def from_wire(self, request):
        """Decode the wire request. (FLUENT)
        
        This actually creates a promise. The first time object.request
        is accessed the promise is realized.
        """
        self.request_ = None
        # TCP comes in with the length for consistency.
        self.raw = isinstance(self.plug, TcpPlug) and request[2:] or request
        return self
    
    def patch_for_test(self):
        """Apply any patches indicated by the settings under CONTROL_KEY.
        
        NOTE: Makes a synchronous request to Redis for CONTROL_KEY. Not intended
              to be turned on in production.
        """
        self.response_config = self.response_config.copy()
        if Request.REDIS is None:
            Request.REDIS = redis.client.Redis(self.response_config.redis_server, decode_responses=True,
                                               socket_connect_timeout=self.response_config.redis_timeout
                                         )
        r = Request.REDIS
        patches = r.hgetall(self.response_config.control_key)
        deletions = set()
        for k in patches.keys():
            if k in self.REDIS_FIXUP_TEST_KEYS:
                if k in patches and patches[k] in self.REDIS_FIXUP_VALUES:
                    patches[k] = self.REDIS_FIXUP_VALUES[patches[k]]
                if k == 'case_folding':
                    # NOTE: For whatever reason, can't apply closures with update()
                    #patches[k] = FOLDERS[patches[k]]
                    deletions.add('case_folding')
                    self.response_config.config['folder'] = FOLDERS[patches[k]]
            else:
                patches[k] = int(patches[k])
        for k in deletions:
            del patches[k]
        self.response_config.config.update(patches)
        self.response_config.config['patched'] = True
        return
    
    def with_config(self, config, stats):
        """Allow the specification of ResponseConfig. (FLUENT)"""
        self.response_config = config
        if config.control_key:
            self.patch_for_test()
        if stats:
            self.timer = stats.start_timer()
        else:
            self.timer = None
        return self
    
    @property
    def request(self):
        """Opportunity to finalize the request promise."""
        if self.request_ is None:
            self.request_ = dns.message.from_wire(self.raw)
            self.raw = None
        return self.request_
    
    def edns_fixup(self):
        """Fix up response EDNS payload size based on configs and the query.
        
        Payload size advertised in the UDP EDNS response is determined as follows:
        
        * No EDNS in request -- No EDNS in response, 512 byte UDP limit
        * EDNS present -- lesser of size advertised in request and MAX_UDP_PAYLOAD
        
        No EDNS is returned with responses over TCP.
        """
        if isinstance(self.plug, TcpPlug):
            self.response.edns = self.NO_EDNS_FLAG
            self.udp_limit = None
            return
        
        # That takes care of TCP...
        #
        # Do we even have EDNS?
        if self.request.edns == self.NO_EDNS_FLAG:
            self.response.edns = self.NO_EDNS_FLAG
            self.udp_limit = self.NO_EDNS_PAYLOAD_SIZE
            return
        
        # Lesser of what's in the query or configured, but at least 512 bytes
        self.response.edns = self.HAS_EDNS_FLAG
        self.udp_limit = min(
                            max( self.request.payload, self.NO_EDNS_PAYLOAD_SIZE ),
                            self.response_config.max_udp_payload
                        )
        self.response.payload = self.udp_limit
        
        return
    
    def formerr(self):
        """FORMERR -- FLUENT"""
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.FORMERR)
        self.edns_fixup()
        return self
        
    def nxdomain(self):
        """NXDOMAIN -- FLUENT"""
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NXDOMAIN)
        self.edns_fixup()
        return self
    
    def servfail(self):
        """SERVFAIL -- FLUENT"""
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.SERVFAIL)
        self.edns_fixup()
        return self
    
    def ttl(self, query):
        ttl = query.ttl
        if ttl is None:
            ttl = self.response_config.default_ttl
        if   ttl < self.response_config.min_ttl:
            ttl = self.response_config.min_ttl
        elif ttl > self.response_config.max_ttl:
            ttl = self.response_config.max_ttl
        return ttl
    
    @staticmethod
    def convert_to_address(v, cls):
        """Honor things that look like either addresses or integers."""
        if type(v) is bytes:
            v = v.decode()
        # Does it look like a "normal" address?
        try:
            addr = cls(v)
            return addr
        except ValueError:
            pass
        # Is it an integer? This will kick a ValueError exception upstairs.
        return cls(int(v))
    
    def noerror(self, query):
        """NOERROR / success -- FLUENT"""
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)

        config = self.response_config
        ttl = self.ttl(query)
        
        # NOTE: Whether or not the query type is allowed is checked upstream
        #       in controller.Controller.process_pending_queue()
        # NOTE: Using rdata_class and rdata_type inside of closures is ok here
        #       because the closure changes accordingly.
        rdata_class = rdcls.IN
        rdata_type = rdtype.TXT
        convert = lambda v: type(v) is str and v.encode() or v
        to_rdata = lambda v: TXT(rdata_class, rdata_type, [v])

        query_type = self.request.question[0].rdtype
        if not (config.all_queries_as_txt or query_type == rdtype.TXT):
            rdata_type = query_type
            to_rdata = lambda v: rdata.from_text(rdata_class, rdata_type, v)
            if   rdata_type == rdtype.A:
                convert = lambda v:self.convert_to_address(v,IPv4Address).exploded
            elif rdata_type == rdtype.AAAA:
                convert = lambda v:self.convert_to_address(v,IPv6Address).exploded
        rdatas = []
        for value in query.results():
            try:
                v = to_rdata( convert( value ) )
                if v:
                    rdatas.append(v)
            except ValueError:
                logging.warning('Unprocessable value for {} ({}) from {}'.format(
                    self.request.question[0].name.to_text(), rdtype.to_text(rdata_type), self.plug.query_address
                ))

        if len(rdatas):
            answer_rrset = response.find_rrset(
                                        response.answer, self.request.question[0].name,
                                        rdata_class, rdata_type, create=True
                                    )
            answer_rrset.ttl = ttl
            for rr in rdatas:
                if rdata_type == rdtype.TXT:
                    # There is really ever only one string because we set it explicitly above.
                    rd = b''.join(rr.strings)
                    if len(rd) > self.response_config.max_value_payload:
                        logging.warn('Max single value length ({}) exceeded for {} from {}'.format(
                            self.response_config.max_value_payload, self.request.question[0].name.to_text(), self.request.plug.query_address
                        ))
                        if self.response_config.return_partial_value:
                            rr.strings[0] = rd[:self.response_config.max_value_payload]
                        else:
                            continue
                answer_rrset.add(rr)

        self.edns_fixup()

        return self
    
    def truncate_response(self, limit, udp=True):
        """Truncates a response and sets the TC flag.
        
        This is simplistic because it assumes that there is nothing
        other than the ANSWER section which is populated.
        """
        question = self.request.question[0]
        response = self.response
        answer_rrset = response.find_rrset(
                                        response.answer, self.request.question[0].name,
                                        question.rdclass, question.rdtype, create=True
                                    )
        to_wire = FunctionResult(
                        lambda fr: not (fr.exc or len(fr.result) > limit),
                        response.to_wire, max_size=65535, exceptions=TooBig
                    )
        while not to_wire():
            if to_wire.exc:
                if isinstance(to_wire.exc, TooBig):
                    wire_len = 65535 * 2
                else:
                    raise to_wire.exc
            wire_len = len(to_wire.result)
            if not udp and wire_len > limit:
                if not self.response_config.return_partial_tcp:
                    logging.error('TCP payload size exceeded for {} from {}'.format(
                        self.request.question[0].name.to_text(), self.request.plug.query_address
                    ))
                    response.set_rcode(rcode.SERVFAIL)
            overage = limit / wire_len
            new_length = floor(len(answer_rrset) * overage)
            for rr in list(answer_rrset)[new_length:]:
                answer_rrset.remove(rr)
            if not len(answer_rrset):
                break
        
        if udp:
            response.flags |= dns.flags.TC
            to_wire()
        
        return to_wire.result        

    def to_wire(self):
        """Converts a response to wire format and returns it."""
        try:
            wire = self.response.to_wire()
            force_truncate = False
        except TooBig:
            force_truncate = True
        if isinstance(self.plug, TcpPlug):
            if force_truncate or len(wire) > self.response_config.max_tcp_payload:
                wire = self.truncate_response(self.response_config.max_tcp_payload, udp=False)
            return len(wire).to_bytes(2, byteorder='big') + wire
        
        if force_truncate or len(wire) > self.udp_limit:
            wire = self.truncate_response(self.udp_limit)
            
        return wire

class DnsIOControl(object):
    """Control which needs to be referenced in multiple places."""
    def __init__(self, loop, pending, responses, response_config, statistics):
        self.event_loop = loop
        self.pending_queue = pending
        self.response_queue = responses
        self.response_config = response_config
        if statistics is not None:
            self.request_stats = Request.statistics_collector(statistics)
            self.tcp_enqueue_stats = statistics.Collector('tcp_enqueue')
            self.write_stats = statistics.Collector('writes')
        else:
            self.request_stats = None
            self.tcp_enqueue_stats = None
            self.write_stats = None
        # udp_transport -- create_udp_listener()
        # tcp_transport -- create_tcp_listener()
        # write_controller -- create_write_controller()
        return

    #def add_to_pending_queue(self, request):
        #if self.pending_queue.full():
            #if request.timer is not None:
                #request.timer.stop('udp_drop')
            #return
        #self.pending_queue.put_nowait(request)
        #return

    def create_udp_handler(self, request, addr ):
        if self.pending_queue.full():
            # Drops it on the floor.
            if self.request_stats is not None:
                self.request_stats.start_timer().stop('udp_drop')
            return
        request = Request.UdpIO(addr, self.udp_transport).from_wire(request).with_config(self.response_config, self.request_stats)
        self.pending_queue.put_nowait(request)
        return
        
    def create_udp_listener(self, interface, port):
        service = self.event_loop.create_datagram_endpoint( UDPListener, local_addr=(interface, port) )
        try:
            transport, listener = self.event_loop.run_until_complete(service)
        except PermissionError:
            logging.fatal('Permission Denied creating UDP listener on {}:{} (are you root?)'.format(interface, port))
            sys.exit(1)
        except OSError as e:
            logging.fatal('{} while creating UDP listener on {}:{}'.format(e, interface, port) )
            sys.exit(1)

        listener.control = self
        self.udp_transport = transport

        return
        
    async def handle_tcp_requests(self, reader, writer):
        """Multiple requests are possible on a TCP connection."""
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> handle_tcp_requests')

        connection = TcpConnection(reader, writer)        
        while True:
            request = await reader.read(2)
            request_length = int.from_bytes(request, byteorder='big')
            if not request_length:
                break
            while request_length:
                partial = await reader.read(request_length)
                if not len(partial):
                    break
                request += partial
                request_length -= len(partial)
            if not len(partial):
                break
            if self.tcp_enqueue_stats is not None:
                timer = self.tcp_enqueue_stats.start_timer()
            else:
                timer = None
                
            request = Request.TcpIO(connection).from_wire(request).with_config(self.response_config, self.request_stats)

            # The reason we do this for the TCP case and not the UDP case is backpressure.
            if PRINT_COROUTINE_ENTRY_EXIT:
                # NOTE: This finalizes the request here, normally it would occur later in processing.
                PRINT_COROUTINE_ENTRY_EXIT('> handle_tcp_requests ({})'.format(request.request.id))

            await self.pending_queue.put(request)
            
            if timer is not None:
                timer.stop()

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< handle_tcp_requests ({})'.format(request.request.id))
            
        connection.close()

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> handle_tcp_requests')
        return
        
    def create_tcp_listener(self, interface, port, tcp_max_read):
        service = asyncio.start_server(self.handle_tcp_requests, interface, port, loop=self.event_loop, limit=tcp_max_read)
        self.tcp_transport = self.event_loop.run_until_complete(service)
        return
        
    async def write_control(self):
        """Write Control.
        
        The effect of this is to implement backpressure when TCP connections
        aren't reading data
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> write_control')
        class TaskSelected(Exception):
            pass
        tcp_pending = asyncio.Semaphore(self.response_queue[TcpPlug].maxsize, loop=self.event_loop)

        async for writer in self.response_queue.get(tcp_pending):

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> write_control ({})'.format(writer.request.id))

            if self.write_stats is not None:
                write_timer = self.write_stats.start_timer()
            
            # Send the selected response.
            try:
                wire_task = writer.to_wire()
            except Exception as e:
                question = writer.request.question[0]
                logging.error('Conversion to wire format failed: {} {} {} {}\n{}'.format(
                    e,
                    writer.plug.query_address, question.name.to_text(), rdtype.to_text(question.rdtype),
                    traceback.format_exc()
                ) )
                if isinstance(writer.plug, TcpPlug):
                    tcp_pending.release()
                if writer.timer is not None:
                    writer.timer.stop(timer_category)
                    write_timer.stop()
                if PRINT_COROUTINE_ENTRY_EXIT:
                    PRINT_COROUTINE_ENTRY_EXIT('< write_control ({})'.format(writer.request.id))
                continue

            if isinstance(writer.plug, TcpPlug):
                writer.plug.semaphore = tcp_pending
                timer_category = 'tcp'
            else:
                timer_category = 'udp'
            
            self.event_loop.create_task(
                writer.plug.write(
                    wire_task
            ) )
            
            if writer.timer is not None:
                writer.timer.stop(timer_category)
                write_timer.stop()
        
            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('< write_control ({})'.format(writer.request.id))

        # Should never exit.
        raise RuntimeError("Control loop should never exit.")
    
    def create_write_controller(self):
        self.write_controller = self.event_loop.create_task(self.write_control())
        return

class UDPListener(asyncio.DatagramProtocol):
    """This is required by asyncio.
    
    It acquires a DnsIOControl object after it is instantiated. The handler
    routine for datagrams is part of that object.
    """
    #def connection_made(self, transport):
        #return
    
    def datagram_received(self, request, addr):
        self.control.create_udp_handler( request, addr )
        return

class DnsResponseQueue(object):
    """Encapsulates the TCP and UDP response queues.
    
    With a convenience method for choosing the appropriate queue.
    """
    
    def __init__(self, queue_depth, loop):
        self.queue = {
                cls: asyncio.Queue(queue_depth, loop=loop)
                for cls in DnsPlug.CLASSES
            }
        self.event_loop = loop
        return
    
    @property
    def queues(self):
        """A list of the queues with printable keys. (GENOBJ)"""
        return ((k.__name__, v) for k,v in self.queue.items())
            
    def __getitem__(self, key):
        """Return the correct queue based on the plugin class."""
        return self.queue[key]
    
    async def tcp_get(self, semaphore):
        """Retrieves something from the TCP queue after acquiring the semaphore."""
        await semaphore.acquire()
        task = await self.response_queue[TcpPlug].get()
        return task.result()
    
    async def get(self, tcp_pending):
        """Async genfunc returning (gated) write tasks to process."""
        done = set()
        pending = set()
        while True:
            while len(done):
                # Could be 2 done...
                task = done.pop()
                yield task.result()
            
            # Something could be done by now. There is at most one item in
            # the task list.
            if len(pending):
                task = pending.pop()
                if task.done():
                    yield task.result()
                else:
                    pending.add(task)
                
            # Clear out the UDP Queue
            try:
                writer = self[UdpPlug].get_nowait()
                yield writer
                continue
            except asyncio.QueueEmpty:
                pass
            
            # Refill the pending tasks
            needed = DnsPlug.CLASSES - { type(item) for item in pending }
            for item in needed:
                pending.add(self[item].get())

            done, pending = await asyncio.wait(pending, loop=self.event_loop, return_when=asyncio.FIRST_COMPLETED)

        # Should never exit.
        raise RuntimeError('Control loop should never exit.')
    
    async def write(self, req):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> DnsResponseQueue.write ({})'.format(req.request.id))

        await self.queue[type(req.plug)].put(req)

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< DnsResponseQueue.write ({})'.format(req.request.id))
        return
    
class DnsIO(object):
    """Encapsulates handling of DNS requests."""

    TCP_MAX_READ = 2048 # More than a standard ethernet frame.
    PORT = 53
    
    def __init__(self, interface, loop, pending, responder, response_config, statistics):

        self.controller = DnsIOControl( loop, pending, responder, response_config, statistics )

        # UDP listener
        self.controller.create_udp_listener( interface, self.PORT )
        
        # TCP listener
        self.controller.create_tcp_listener( interface, self.PORT, self.TCP_MAX_READ )
        
        # Write Controller
        self.controller.create_write_controller()
        
        return
        
    def close(self):
        #self.controller.write_controller.close()
        self.controller.udp_transport.close()
        self.controller.tcp_transport.close()
        return

#################################################################################
# REDIS QUERY
#################################################################################
    
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
    
    def __init__(self, query, folder):
        if len(self.PARAMETERS) != len(query):
            raise RedisParameterError()
        for param, value in zip(self.PARAMETERS, query):
            if not len(value):
                raise RedisParameterError()
            object.__setattr__(self, param, value)
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

class RedisSMembersQuery(RedisBaseQuery):
    PARAMETERS = ( 'key', 'operand' )
    MULTIVALUED = True

    def query(self, conn):
        """Returns a list; may be empty."""
        return conn.smembers(self.key)
        
REDIS_QUERY_TYPES = {
        b'get'     : RedisGetQuery,
        b'hget'    : RedisHGetQuery,
        b'hkeys'   : RedisHKeysQuery,
        b'keys'    : RedisKeysQuery,
        b'lindex'  : RedisLIndexQuery,
        b'lrange'  : RedisLRangeQuery,
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

    def __init__(self, server, loop):
        """We allow a backlog of one extra query."""
        self.event_loop = loop
        self.semaphore = asyncio.Semaphore( self.WORKERS+1, loop=loop )
        self.pool = ThreadPoolExecutor(self.WORKERS)
        self.redis = redis.client.Redis(server, decode_responses=False,
                                        socket_connect_timeout=self.CONNECT_TIMEOUT
                                       )
        return
    
    def redis_job(self, query, callback):
        """The actual job run in the thread pool.
        
        POSSIBLE SEMAPHORE LEAK
        
        We only release the semaphore if there was no exception kicked, and so
        repeated exceptions could result in a deadlock. This is intentional to
        make the situation self-limiting in the case of adversarial input and
        should be revisited.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> redis_job')
            
        try:
            exc = result = ttl = None
            result = query.query(self.redis)
            query.resolve_ttl(self.redis)
            query.store_result( result, exc )
        except redis.exceptions.ConnectionError as e:
            logging.error('redis.exceptions.ConnectionError: {}'.format(e))
            exc = e
        except Exception as e:
            logging.error('{}:\n{}'.format(e, traceback.format_exc()))
            exc = e
        asyncio.run_coroutine_threadsafe( self.finish_job(exc, result, callback), self.event_loop )
        
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< redis_job')
        return
    
    async def finish_job(self, exc, result, callback):
        """Part II of redis_job() runs as a coroutine
        
        ...rather than in the thread pool.
        """
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> finish_job')

        await callback
        # TODO: Do we want to release the semaphore if this happens... or not?
        if exc is None:
            self.semaphore.release()

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< finish_job')
        return
    
    async def submit(self, query, callback):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> submit ({})'.format(query.id))

        await self.semaphore.acquire()
        self.event_loop.run_in_executor(self.pool, self.redis_job, query, callback)

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< submit ({})'.format(query.id))
        return
    
    
    