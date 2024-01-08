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

#
# THESE VALUES ARE OPTIONAL -- defaults are shown
#

# The depth of various queues which produce "back pressure"
#MAX_PENDING = 50

# Maximum UDP size we accept and advertise in EDNS responses. Avoid frags!
#MAX_UDP_PAYLOAD = 1200
# Maximum TCP size (architectural limit)
#MAX_TCP_PAYLOAD = 60000
# Maximum individual value size (architectural limit)
#MAX_VALUE_PAYLOAD = 255
# If true, partial TCP payloads are returned with NOERROR instead of SERVFAIL
#RETURN_PARTIAL_TCP = False
# If true, individual values are truncated rather than omitted if too large.
#RETURN_PARTIAL_VALUE = False
# If True, then if MAX_TCP_PAYLOAD would be exceeded (even if, or especially if,
# the request is via UDP) the server returns NXDOMAIN instead of SERVFAIL. This
# does not affect logging.
#NXDOMAIN_FOR_SERVFAIL = False

# Regardless of the query type, the result is always TXT if True.
#ALL_QUERIES_AS_TXT = False
# One of None / lower / upper / escape. See the documentation.
#CASE_FOLDING = None

# Maximum allowable TTL
#MAX_TTL = 3600
# TTL used when pulling it from the Redis key doesn't make sense.
#DEFAULT_TTL = 30
# Minimum allowable TTL
#MIN_TTL = 5

# Debouncing. If True then multiple requests from the same host are suppressed,
# even with unique query ids.
#DEBOUNCE = False

# How often to print statistics, in seconds. The practical minimum is
# 60 seconds.
#STATS = 3600
# You can set it to None to disable statistics.
#STATS = None
# How often to report queue depths, in seconds.
#QUEUE_DEPTH = None

# If defined, then the minimum logging level is set.
#LOG_LEVEL = None
# To set it to INFO:
#import logging
#LOG_LEVEL = logging.INFO

# If set to True, then instead of returning DNS errors the error message is
# encoded in a CNAMEd TXT record.
#ENABLE_ERROR_TXT = False

# If set to True, then the semaphore leaks and Redis queries cease if Redis
# queries are triggering exceptions. The notion is to attenuate adversarial
# attacks against Redis. It's up to you: if you want RKVDNS to cease harassing
# Redis if it's kicking exceptions, set this to true; then RKVDNS will hang.
#LEAK_SEMAPHORE_IF_EXCEPTION = False

# NS and SOA record synthesis.
# 
# Since as far as The DNS is concerned this is a "zone" and all respectable
# zones should have NS and SOA records we provide the means to synthesize them
# here.
#
# NS Record. Set this to the FQDN of the RKVDNS instance. Do NOT set it to
# the name of the zone (unless they're the same). The synthesized record will
# look like the following (in "zone file format"):
#
#    <ZONE> <DEFAULT_TTL> IN NS <RKVDNS_FQDN>
#
# Utilizing the various defaults given in this sample file, an actual NS
# record would look like:
#
#    proxy.redis.example.com. 30 IN NS redis.example.com.
#
# It is assumed that redis.example.com as A/AAAA records.
#
# RKVDNS_FQDN = None
# RKVDNS_FQDN = 'redis.example.com'
#
# SOA Record. Set this to the "contact name", which is to say to an administrator
# email address with the "@" replaced by a ".". So for instance
# dns-admin@example.com would be entered as dns-admin.example.com. The synthesized
# record will look like the following (in "zone file format"):
#
#    <ZONE> <DEFAULT_TTL> IN SOA <RKVDNS_FQDN> <SOA_CONTACT> 1 <DEFAULT_TTL> <DEFAULT_TTL> 86400 <MIN_TTL>
#
# Utilizing the various defaults given in this sample file, an actual SOA
# record would look like:
#
#    proxy.redis.example.com 30 IN SOA redis.example.com dns-admin.example.com 1 30 30 86400 5
#
# Both SOA_CONTACT and RKVDNS_FQDN must be specified (and not the default of None)
# in order for SOA records to be synthesized.
# SOA_CONTACT = None
# SOA_CONTACT = 'dns-admin.example.com'

# Controls the level of conformance. If True then error reporting via responses is
# sacrificed in favor of maximal generic reporting conformant with what modern recursing
# nameservers expect on behalf of their cloud overlords. Mostly affects the qname minimization
# dance.
# CONFORMANCE = False

# Define in order to run tests. It should be considered a key
# prefix. The key itself will point to a redis hash. Additional
# keys will be created using this as a prefix.
# NOTE: Do NOT define this EXCEPT to run tests due to performance
#       impacts.
#CONTROL_KEY = None
# NOTE: This key prefix should be considered to be CASE INSENSITIVE, as
#       one of the features of this utility is case folding.
#CONTROL_KEY = 'tests'

#
# THESE VALUES MUST BE DEFINED
#

# Interface the agent listens on.
INTERFACE = '127.0.0.1'
# Address of the Redis server.
REDIS_SERVER = '127.0.0.1'

# Zone in which we publish data.
ZONE = 'proxy.redis.example.com'

