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

#
# Capitalization folding has four potential settings, as shown in FOLDERS.
# The escape folder in particular requires special treatment.
#
ESCAPE_HANDLERS = (
        lambda x:x,
        lambda x:x.upper(),
        lambda x:x.lower()
    )
    
def escape_folder(v):
    """Escaping case folder.
    
    Or un-folder. The first three octets in the key define escapes:
    
      octet 0:  Escapes itself and the other two octets.
      octet 1:  Forces the following octet to be uppercase.
      octet 2:  Forces the following octet to be lowercase.
      
    (For those who work with electronic health records, I feel your pain!)
    """
    escapes = { k:ESCAPE_HANDLERS[i] for i,k in enumerate(v[:3]) }

    built = []
    state = None
    for c in v[3:]:
        if state is None:
            if c in escapes:
                state = c
            else:
                built.append(c)
            continue
        built.append( ord(escapes[state](chr(c))) )
        state = None
        
    return bytes(built)
    
FOLDERS = {
        None:     lambda x:x,
        'lower':  lambda x:x.lower(),
        'upper':  lambda x:x.upper(),
        'escape': lambda x:escape_folder(x)
    }
