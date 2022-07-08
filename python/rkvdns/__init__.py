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

class FunctionResult(object):
    """Semantic sugar for loop conditionals."""
    def __init__(self, success, func, *args, exceptions=Exception, **kwargs):
        self.success = success
        self.exceptions = exceptions
        self.func = func
        self.args = args
        self.kwargs = kwargs
        # self.result   
        # self.exc
        return
    
    def __call__(self):
        try:
            self.result = None
            self.exc = None
            self.result = self.func(*self.args, **self.kwargs)
        except self.exceptions as e:
            self.exc = e
        return self.success(self)
    