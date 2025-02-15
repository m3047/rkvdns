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
"""I/O Operations for DNS requests.

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

import sysconfig

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

import sys
import logging
import traceback
from math import floor

import asyncio

if PYTHON_IS_311:
    from asyncio import CancelledError
else:
    from concurrent.futures import CancelledError

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
import dns.name

# Required by Request.patch_for_test()
import redis

from ipaddress import IPv4Address, IPv6Address
from random import random

from .. import FunctionResult, FOLDERS
from ..statistics import StatisticsCollector, UndeterminedStatisticsCollector

# Start/end of coroutines. Delayed import happens in DnsIO.__init__()
#from . import PRINT_COROUTINE_ENTRY_EXIT

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
        self.query_address = address[0]
        self.transport = transport
        self.writing = None     # Set prior to calling write()
        return
    
    @property
    def is_connected(self):
        """Only applies to TCP, so UDP always returns True."""
        return True
        
    async def write(self, response, timer, active_writers):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> UdpPlug.write')

        self.transport.sendto( response, self.address )
        
        if timer is not None:
            timer.stop()

        self.writing = None
        active_writers.remove(self)
        
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< UdpPlug.write')
        return

class TcpPlug(DnsPlug):
    
    def __init__(self, stream):
        self.semaphore = None   # Set prior to calling write()
        self.stream = stream
        self.query_address = stream.writer.get_extra_info('peername')
        self.writing = None     # Set prior to calling write()
        return

    @property
    def is_connected(self):
        return self.stream.writer is not None
    
    async def write(self, response, timer, active_writers):
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
        
        if timer is not None:
            timer.stop()
            
        self.writing = None
        active_writers.remove(self)

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< TcpPlug.write')
        return

DnsPlug.CLASSES = {UdpPlug, TcpPlug}

class TcpConnection(object):
    """The TcpPlug.stream object.
    
    As part of its encapsulation function, maintains a watchdog timer which will
    close the connection after a DEFAULT_TIMEOUT + TIMEOUT_PADDING period of inactivity.
    """
    DEFAULT_TIMEOUT = 30
    TIMEOUT_PADDING = 1
    
    def __init__(self, reader, writer, event_loop, timeout=None):
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.expiry = None
        self.watchdog = None
        self.event_loop = event_loop
        self.reader = reader
        self.writer = writer
        return
    
    @property
    def closed(self):
        return self.writer is None
    
    def update_for_test(self, timeout):
        """Update timeout for testing.
        
        Used ONLY for testing, not to be used in production.
        """
        self.watchdog.cancel()
        self.watchdog = None
        self.timeout = timeout
        return
    
    def update_watchdog_timer(self):
        self.expiry = self.event_loop.time() + self.timeout
        if not self.watchdog:
            self.create_watchdog()
        return
    
    def create_watchdog(self):
        self.watchdog = self.event_loop.call_at( self.expiry + self.TIMEOUT_PADDING, self.timeout_watchdog )
        return
    
    def timeout_watchdog(self):
        if self.event_loop.time() < self.expiry:
            self.create_watchdog()
            return
        self.watchdog = None
        self.close_()
        return
    
    def read(self, n):
        """Read bytes from the stream. (awaitable)
        
        The timeout is reset each time this is called.
        """
        self.update_watchdog_timer()
        return self.reader.read(n)
    
    def close(self):
        if self.watchdog:
            self.watchdog.cancel()
            # Callback not an awaitable task.
            #try:
                #await self.watchdog
            #except CancelledError:
                #pass
            self.watchdog = None
        self.close_()

    def close_(self):
        if self.closed:
            return
        self.writer.close()
        self.reader = self.writer = None
        return

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

    #
    # Anything which is string is handled here, with special handling for the strings
    # "True", "False", "None".
    REDIS_FIXUP_TEST_KEYS = ('return_partial_tcp', 'return_partial_value',
                             'all_queries_as_txt', 'case_folding', 'enable_error_txt',
                             'incrementing', 'debounce', 'conformance'
                            )
    REDIS_FIXUP_VALUES = { 'False':False, 'True':True, 'None':None }
    REDIS_FIXUP_FQDN_KEYS = ('zone', 'rkvdns_fqdn', 'soa_contact')
    #
    # Anything not enumerated above is expected to be integer-valued (or capable of being
    # converted to an integer value.
    #
    
    RDATA_HEADER_LENGTH = 13
    
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
        
        # NOTE: The following diagnostics provide timing, iteration and size statistics
        # for requests. Uncomment the definition of CountingDict and the occurrences
        # of proc_stats in Request and DnsIOControl.write_control.
        #self.proc_stats = CountingDict()

        return

    @classmethod
    def UdpIO(cls, *args):
        """A Request with a UdpPlug."""
        return cls( UdpPlug(*args) )
    
    @classmethod
    def TcpIO(cls, *args):
        """A Request with a TcpPlug."""
        return cls( TcpPlug(*args) )
    
    def from_wire(self, request):
        """Decode the wire request. (FLUENT)
        
        This actually creates a promise. The first time object.request
        is accessed the promise is realized.
        """
        self.request_ = None
        self.qlabels_ = None
        self.qtype_ = None
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
        # NOTE: This all looks a little strange. Bear in mind that while the values are pythonic
        # in configuration.py and in tests/end_to_end.py the patches get written to redis
        # and so what we get back is (mostly) strings and so we have to convert back to the proper
        # python types.
        for k in patches.keys():
            if k in self.REDIS_FIXUP_TEST_KEYS:
                if k in patches and patches[k] in self.REDIS_FIXUP_VALUES:
                    patches[k] = self.REDIS_FIXUP_VALUES[patches[k]]
                if k == 'case_folding':
                    # NOTE: For whatever reason, can't apply closures with update()
                    #patches[k] = FOLDERS[patches[k]]
                    deletions.add('case_folding')
                    self.response_config.config['folder'] = FOLDERS[patches[k]]
            elif k in self.REDIS_FIXUP_FQDN_KEYS:
                patches[k] = patches[k].split('.')
            else:
                try:
                    patches[k] = int(patches[k])
                except:
                    patches[k] = eval(patches[k])
        for k in deletions:
            del patches[k]
        self.response_config.config.update(patches)
        return
    
    def with_config(self, config, stats):
        """Allow the specification of ResponseConfig. (FLUENT)"""
        self.response_config = config
        if config.control_key:
            self.patch_for_test()
            self.response_config.config['patched'] = True
        else:
            self.response_config.config['patched'] = False
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

    @property
    def qlabels(self):
        if self.qlabels_ is None:
            self.qlabels_ = list(self.request.question[0].name.labels)
            if not self.qlabels_[-1]:
                del self.qlabels_[-1]
        return self.qlabels_
    
    @property
    def qtype(self):
        if self.qtype_ is None:
            self.qtype_ = self.request.question[0].rdtype
        return self.qtype_
    
    def edns_fixup(self):
        """Fix up response EDNS payload size based on configs and the query.
        
        Payload size advertised in the UDP EDNS response is determined as follows:
        
        * No EDNS in request -- No EDNS in response, 512 byte UDP limit
        * EDNS present -- lesser of size advertised in request and MAX_UDP_PAYLOAD
        
        No EDNS is returned with responses over TCP.
        """
        if isinstance(self.plug, TcpPlug):
            self.response.use_edns(self.NO_EDNS_FLAG)
            self.udp_limit = None
            return
        
        # That takes care of TCP...
        #
        # Do we even have EDNS?
        if self.request.edns == self.NO_EDNS_FLAG:
            self.response.use_edns(self.NO_EDNS_FLAG)
            self.udp_limit = self.NO_EDNS_PAYLOAD_SIZE
            return
        
        # Lesser of what's in the query or configured, but at least 512 bytes
        self.udp_limit = min(
                            max( self.request.payload, self.NO_EDNS_PAYLOAD_SIZE ),
                            self.response_config.max_udp_payload
                        )
        self.response.use_edns(self.HAS_EDNS_FLAG, payload=self.udp_limit)
        
        return
    
    def cname_error(self, text):
        response = self.response
        error_name = '{}.error.{}.'.format(int(random()*1000000000), b'.'.join(self.response_config.zone).decode())

        cname_rrset = response.find_rrset(
                                    response.answer, self.request.question[0].name,
                                    rdcls.IN, rdtype.CNAME, create=True
                                )
        cname_rrset.ttl = self.response_config.default_ttl
        cname_rrset.add( rdata.from_text( rdcls.IN, rdtype.CNAME, error_name ) )

        error_name = dns.name.from_text(error_name)
        error_rrset = response.find_rrset(
                                    response.answer, error_name,
                                    rdcls.IN, rdtype.TXT, create=True
                                )
        error_rrset.ttl = self.response_config.default_ttl
        error_rrset.add( TXT( rdcls.IN, rdtype.TXT, [ text.encode() ] ) )
        
        return
    
    def soa_record(self, rrset):
        """Adds an SOA record to the rrset for the designated section.

        The minimum TTL specified on this record is used to determine the TTL
        for negative responses (NXDOMAIN and ANSWER:0). To that end we use
        what is configured as the DEFAULT_TTL rather than the MIN_TTL. This comports
        with the fact that the DEFAULT_TTL is what is returned with e.g. a keys
        query, where no TTL is associated with the entity by Redis; the most common
        cause of ANSWER:0 in our use case is a keys query returning no matches.
        
        Note that this is set with the rrset TTL which is applied to the SOA record,
        not any of the TTLs supplied with the SOA record itself.
        """
        config = self.response_config
        response = self.response
        if not (config.rkvdns_fqdn and config.soa_contact):
            logging.warning('SOA not available for referral, configure RKVDNS_FQDN and SOA_CONTACT.')
            return

        target_rrset = response.find_rrset(
                                    rrset, dns.name.from_text(b'.'.join(config.zone)),
                                    rdcls.IN, rdtype.SOA, create=True
                                )
        target_rrset.ttl = config.default_ttl
        target_rrset.add(
                rdata.from_text(rdcls.IN, rdtype.SOA,
                                '{}. {}. 1 {} {} 86400 {}'.format(
                                    '.'.join(config.rkvdns_fqdn),
                                    '.'.join(config.soa_contact),
                                    config.max_ttl, config.max_ttl, config.min_ttl
                            )
                    )
            )
        return
    
    def error_response(self, code, text, referral):
        response = self.response = dns.message.make_response(self.request)
        if referral:
            self.soa_record( response.authority )
        if self.response_config.enable_error_txt and text is not None:
            response.set_rcode(rcode.NOERROR)
            self.cname_error( text )
        else:
            response.set_rcode(code)
        self.edns_fixup()
        return

    def formerr(self, text=None):
        """FORMERR -- FLUENT"""
        self.error_response(rcode.FORMERR, text, False)
        return self

    def notimp(self, text=None):
        """NOTIMP -- FLUENT"""
        self.error_response(rcode.NOTIMP, text, False)
        return self
        
    def nxdomain(self, text=None, referral=True):
        """NXDOMAIN -- FLUENT
        
        Parameters:
            text        Optional text for CNAME error messaging.
            referral    If True, the SOA is included in the ADDITIONAL section.
        """
        self.error_response(rcode.NXDOMAIN, text, referral)
        return self
    
    def empty_non_terminal(self, referral=True):
        """Empty Non-Terminal -- FLUENT"""
        config = self.response_config
        if not (config.rkvdns_fqdn and config.soa_contact):
            return self.servfail('SOA not available')
        
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)
        
        if referral:
            self.soa_record( response.authority )
            
        self.edns_fixup()

        return self
    
    def servfail(self, text=None):
        """SERVFAIL -- FLUENT"""
        self.error_response(rcode.SERVFAIL, text, False)
        return self

    def generated_answer(self, results):
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)
        
        self.answer_from_list( results, self.ttl(None) )
        self.edns_fixup()

        return self

    def soa(self):
        config = self.response_config
        if not (config.rkvdns_fqdn and config.soa_contact):
            return self.servfail('SOA not available')
        
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)
        
        self.soa_record( response.answer )
        self.edns_fixup()

        return self
    
    def ns(self):
        config = self.response_config
        if not config.rkvdns_fqdn:
            return self.servfail('NS not available')

        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)

        answer_rrset = response.find_rrset(
                                    response.answer, self.request.question[0].name,
                                    rdcls.IN, rdtype.NS, create=True
                                )
        answer_rrset.ttl = config.default_ttl
        answer_rrset.add(
                rdata.from_text(rdcls.IN, rdtype.NS,
                                '{}.'.format( '.'.join(config.rkvdns_fqdn) )
                    )
            )

        self.edns_fixup()

        return self
    
    def ttl(self, query=None):
        ttl = None
        if query is not None:
            ttl = query.ttl
        if ttl is not None and ttl <= 0:
            ttl = None
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
    
    def payload_size_precalc(self, results):
        """Is the number of records returned vaguely sane?
        
        Two things happen here. First if it's completely not sane the method
        returns False. Second if it's not sane, the results
        list is truncated to minimize downstream processing.
        
        The precalculation consists of the sum of:
        
        * the length of result strings
        * 13 * the number of strings
        * the length of the qname
        """
        config = self.response_config
        
        all_results = sum( len(x) for x in results )
        headers = len(results) * self.RDATA_HEADER_LENGTH
        qname = len(self.request.question[0].name.to_text())
        # There's an additional 20 bytes, give or take, which is not accounted for.
        
        length = all_results + headers + qname
        
        if length > config.max_tcp_payload and not config.return_partial_tcp:
            return False
        
        # We do this because we're going to truncate anyway in this case and
        # return TC=1 but this makes it go faster.
        if isinstance(self.plug, UdpPlug) and length > config.max_udp_payload:
            length = qname
            for i in range(len(results)):
                length += self.RDATA_HEADER_LENGTH + len(results[i])
                if length > config.max_udp_payload:
                    break
            
            # 2 is a magic number, but it's just a ballpark, "just enough". The
            # overages we're truly concerned about are massive: 100s or 1000s. The
            # point of triggering an overage is to cause TC=1 to be emitted.
            del results[i+2:]
        
        return True
    
    TXT_CONVERTERS = {
            str:    lambda v: v.encode(),
            bytes:  lambda v: v,
            int:    lambda v: str(v).encode(),
            tuple:  lambda v: v
        }

    def noerror(self):
        """NOERROR / success -- FLUENT"""
        response = self.response = dns.message.make_response(self.request)
        response.set_rcode(rcode.NOERROR)

        all_ones = 2**16 - 1
        response.flags &= all_ones ^ (dns.flags.RD | dns.flags.RA)
        response.flags |= (dns.flags.QR | dns.flags.AA)

        self.edns_fixup()

        return self
    
    @staticmethod
    def to_rdata_txt( v ):
        """Make TXT rdata.
        
        TXT rdata can be single strings, or preserved lists of strings.
        """
        if type(v) is not tuple:
            v = [ v ]
        return TXT(rdcls.IN, rdtype.TXT, v)
       
    def answer_from_list(self, results, ttl):
        """Successful Response built from a list of records.
        
        Used to be part of noerror(), now deferred.
        """
        config = self.response_config
        
        # NOTE: Whether or not the query type is allowed is checked upstream
        #       in controller.Controller.process_pending_queue()
        # NOTE: Using rdata_class and rdata_type inside of closures is ok here
        #       because the closure changes accordingly.
        convert = lambda v: self.TXT_CONVERTERS[type(v)](v)
        to_rdata = self.to_rdata_txt

        rdata_class = rdcls.IN
        rdata_type = rdtype.TXT
        query_type = self.request.question[0].rdtype
        if not (config.all_queries_as_txt or query_type == rdtype.TXT):
            rdata_type = query_type
            to_rdata = lambda v: rdata.from_text(rdata_class, rdata_type, v)
            if   rdata_type == rdtype.A:
                convert = lambda v:self.convert_to_address(v,IPv4Address).exploded
            elif rdata_type == rdtype.AAAA:
                convert = lambda v:self.convert_to_address(v,IPv6Address).exploded

        rdatas = []
        for value in results:
            try:
                v = to_rdata( convert( value ) )
                if v:
                    rdatas.append(v)
            except ValueError:
                logging.warning('Unprocessable value for {} ({}) from {}'.format(
                    self.request.question[0].name.to_text(), rdtype.to_text(rdata_type), self.plug.query_address
                ))

        if len(rdatas):
            response = self.response
            answer_rrset = response.find_rrset(
                                        response.answer, self.request.question[0].name,
                                        rdata_class, rdata_type, create=True
                                    )
            answer_rrset.ttl = ttl
            for rr in rdatas:
                if rdata_type == rdtype.TXT:
                    # There is really ever only one string because we set it explicitly above.
                    rd = b''.join(rr.strings)
                    if len(rd) > config.max_value_payload:
                        logging.warn('Max single value length ({}) exceeded for {} from {}'.format(
                            config.max_value_payload, self.request.question[0].name.to_text(), self.plug.query_address
                        ))
                        if config.return_partial_value:
                            rr.strings = [ rd[:config.max_value_payload] ]
                        else:
                            continue
                answer_rrset.add(rr)

        return self
    
    def answer_from_query(self, query):
        """Successful Redis query."""
        return self.answer_from_list( query.results(), self.ttl(query) )
    
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
            else:
                wire_len = len(to_wire.result)
            if not udp and wire_len > limit:
                if not self.response_config.return_partial_tcp:
                    logging.error('TCP payload size exceeded for {} from {}'.format(
                        self.request.question[0].name.to_text(), self.plug.query_address
                    ))
                    if self.response_config.enable_error_txt:
                        for rr in list(answer_rrset):
                            answer_rrset.remove(rr)
                        self.cname_error('TCP payload size exceeded')
                        break
                    else:
                        response.set_rcode(rcode.SERVFAIL)
            overage = limit / wire_len
            new_length = floor(len(answer_rrset) * overage * 0.9)
            for rr in list(answer_rrset)[new_length:]:
                answer_rrset.remove(rr)
            if not len(answer_rrset):
                break
        
        if udp:
            response.flags |= dns.flags.TC

        to_wire()
        if to_wire.exc:
            raise to_wire.exc
        
        return to_wire.result

    def to_wire(self, tied_requests):
        """Converts a response to wire format and returns it."""

        if tied_requests is None:
            wire = self.response.to_wire()
            if isinstance(self.plug, TcpPlug):
                return len(wire).to_bytes(2, byteorder='big') + wire
            else:
                return wire
        #
        # From this point forward we're dealing with a successful redis query with a legitimate
        # answer payload.
        #
        if tied_requests.answer is None:
            # Doesn't matter if udp_limit is passed here, it is ignored if not UDP.
            tied_requests.add_answer( self.answer_from_query( tied_requests.query ), self.udp_limit )
        else:
            self.response.answer = tied_requests.answer
            if tied_requests.tc:
                response.flags |= dns.flags.TC
        
        # This is actually the number of rrsets in the answer rather than the actual number
        # of rdatas, but it will also be 0 in the case of ANSWER:0
        if not len(self.response.answer):
            self.soa_record( self.response.authority )
        
        try:
            wire = self.response.to_wire()
            force_truncate = False
        except TooBig:
            force_truncate = True

        if tied_requests.tcp_or_udp == tied_requests.TCP:
            if force_truncate or len(wire) > self.response_config.max_tcp_payload:
                wire = self.truncate_response(self.response_config.max_tcp_payload, udp=False)
                tied_requests.add_answer(self)
            wire = len(wire).to_bytes(2, byteorder='big') + wire
        else:                   #   == tied_requests.UDP
            if force_truncate or len(wire) > self.udp_limit:
                wire = self.truncate_response( self.udp_limit, udp=True )
                tied_requests.add_answer(self, self.udp_limit, tc=True)

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
        self.active_writers = set()
        return

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

        connection = TcpConnection(reader, writer, self.event_loop, self.response_config.tcp_timeout)
        while True:
            request = await connection.read(2)
            request_length = int.from_bytes(request, byteorder='big')
            if not request_length:
                break
            while request_length:
                partial = await connection.read(request_length)
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
            # NOTE: Supports test automation. One request is required to "prime the pump".
            if request.response_config.patched:
                connection.update_for_test( request.response_config.tcp_timeout )

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
            PRINT_COROUTINE_ENTRY_EXIT('< handle_tcp_requests')
        return
        
    def create_tcp_listener(self, interface, port, tcp_max_read):
        service = asyncio.start_server(self.handle_tcp_requests, interface, port, limit=tcp_max_read)
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
        tcp_pending = asyncio.Semaphore(self.response_queue[TcpPlug].maxsize)

        async for writer, tied_requests in self.response_queue.get():

            if PRINT_COROUTINE_ENTRY_EXIT:
                PRINT_COROUTINE_ENTRY_EXIT('> write_control ({})'.format(writer.request.id))

            if self.write_stats is not None:
                write_timer = self.write_stats.start_timer()
            else:
                write_timer = None

            question = writer.request.question[0]

            timer_category = isinstance(writer.plug, TcpPlug) and 'tcp' or 'udp'

            # If TCP and the writer is gone then the client decided we timed out.
            if not writer.plug.is_connected:
                logging.error('Client disconnected, likely timeout: {} {} {}'.format(
                    writer.plug.query_address, question.name.to_text(), rdtype.to_text(question.rdtype)
                ) )
                if writer.timer is not None:
                    writer.timer.stop(timer_category)
                    write_timer.stop()
                if PRINT_COROUTINE_ENTRY_EXIT:
                    PRINT_COROUTINE_ENTRY_EXIT('< write_control ({})'.format(writer.request.id))
                continue
            
            # Send the selected response.
            try:
                wire_task = writer.to_wire( tied_requests )
            except Exception as e:
                logging.error('Conversion to wire format failed: {} {} {} {}\n{}'.format(
                    e,
                    writer.plug.query_address, question.name.to_text(), rdtype.to_text(question.rdtype),
                    traceback.format_exc()
                ) )
                if writer.timer is not None:
                    writer.timer.stop(timer_category)
                    write_timer.stop()
                if PRINT_COROUTINE_ENTRY_EXIT:
                    PRINT_COROUTINE_ENTRY_EXIT('< write_control ({})'.format(writer.request.id))
                continue
            
            if timer_category == 'tcp':
                await tcp_pending.acquire()
                writer.plug.semaphore = tcp_pending

            # Adding the writer to active_writers and pinning the Task into the plug
            # keeps the Task strong until the write finishes and write() can remove
            # itself.
            self.active_writers.add(writer.plug)
            writer.plug.writing = self.event_loop.create_task(
                    writer.plug.write(
                        wire_task, write_timer, self.active_writers
                )   )
            
            if writer.timer is not None:
                writer.timer.stop(timer_category)
        
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
                cls: asyncio.Queue(queue_depth)
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
    
    async def get(self):
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
                # What gets added here will be awaited below by asyncio.wait()
                pending.add( self.event_loop.create_task( self[item].get() ) )

            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

        # Should never exit.
        raise RuntimeError('Control loop should never exit.')
    
    async def write(self, req, tied_requests=None):
        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('> DnsResponseQueue.write ({})'.format(req.request.id))
        
        await self.queue[type(req.plug)].put( (req,tied_requests) )

        if PRINT_COROUTINE_ENTRY_EXIT:
            PRINT_COROUTINE_ENTRY_EXIT('< DnsResponseQueue.write ({})'.format(req.request.id))
        return
    
class DnsIO(object):
    """Encapsulates handling of DNS requests."""

    TCP_MAX_READ = 2048 # More than a standard ethernet frame.
    PORT = 53
    
    def __init__(self, interface, loop, pending, responder, response_config, statistics):
        from . import PRINT_COROUTINE_ENTRY_EXIT
        globals()['PRINT_COROUTINE_ENTRY_EXIT'] = PRINT_COROUTINE_ENTRY_EXIT

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

