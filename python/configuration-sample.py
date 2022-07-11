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

