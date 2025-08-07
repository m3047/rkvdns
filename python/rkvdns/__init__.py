#!/usr/bin/python3
# Copyright (c) 2022,2025 Fred Morris, Tacoma WA USA
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

import sysconfig
import re

PYTHON_IS_311 = int( sysconfig.get_python_version().split('.')[1] ) >= 11

class CountingDict(dict):
    """A dictionary of counters."""
    def inc(self, k, v=1):
        if k not in self:
            self[k] = 0
        self[k] += v
        return

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

def compile_rewrite( rules ):
    """Takes an ordinary string and converts it to a bytecode dictionary.
    
    ...which is the format used by the REWRITE configuration parameter.
    
    CAUTION: If you stray from the ASCII characters you may be surprised by the
    output produced!
    """
    return dict(
            ( kv.encode() for kv in re.split(' *: *', rule) ) for rule in
            re.split(' *, *', rules.strip())
        )

def compile_rwegex( rules ):
    """Creates the compiled regex encapsulating the rewrite rules.
    
    This is run on the result of compile_rewrite().
    """
    return re.compile( b'(' + b'|'.join(rules.keys()) + b')' )

class InvalidRewriteCharactersError(ValueError):
    """Regular expression metacharacters encountered in a match string."""
    pass

# These characters have special meaning within python regular expressions and therefore
# should not occur in the strings to be matched.
INVALID_REWRITE_CHARS = set( b'[].()*?^${}+' )

def prepare_rewrite_rules( rewrite_rules ):
    """Prepare the rewrite rules.
    
    Used in processing the configuration for agent.py. Done this way
    (as a function) to facilitate testing.
    """
    if rewrite_rules is not None:
        if   type(rewrite_rules) is str:
            rewrite_rules = compile_rewrite(rewrite_rules)
        else:
            for k,v in rewrite_rules.copy().items():
                fix = False
                if type(k) is str:
                    fix = True
                    del rewrite_rules[k]
                    k = k.encode()
                if type(v) is str:
                    fix = True
                    v = v.encode()
                if fix:
                    rewrite_rules[k] = v
        match_chars = set( b''.join(rewrite_rules.keys()))
        if match_chars & INVALID_REWRITE_CHARS:
            raise InvalidRewriteCharactersError()
        rewrite_regex = compile_rwegex( rewrite_rules )
    else:
        rewrite_regex = None
    
    return rewrite_rules, rewrite_regex

