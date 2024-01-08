#!/usr/bin/python3
# Copyright (c) 2022-2024 by Fred Morris Tacoma WA
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
"""I/O Operations for both Redis and DNS requests."""

PRINT_COROUTINE_ENTRY_EXIT = None

from .dns import DnsResponseQueue, DnsIO, TcpPlug, UdpPlug, Request
from .redis import RedisIO, RedisQuery, RedisError, RedisParameterError

#################################################################################
# CONFIGS USED TO CONSTRUCT RESPONSES
#################################################################################
    
class ResponseConfig(object):
    """A container of configuration parameters used when constructing responses.
    
    The following parameters are expected, set from corresponding configuration
    values. FOR THE MOST UP TO DATE LIST, see agent.py.
    """
    def __init__(self, **kwargs):
        self.config = kwargs
        return
    
    def __getattr__(self, param):
        return self.config[param]
    
    def copy(self):
        return type(self)(**self.config.copy())
