#!/usr/bin/python3
# Copyright (c) 2025 Fred Morris Tacoma WA USA
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

"""Running These Tests

Most effort goes into the tests in end_to_end.py. The tests in this module test
individual or combinations of components without an operating agent or redis
environment.
"""

import sys
import unittest

if '..' not in sys.path:
    sys.path.insert(0,'..')

import rkvdns

class TestRewrite(unittest.TestCase):
    """Tests that different forms of rewrite rules do the right thing."""

    def test_binary(self):
        """The default case where everything is explicit."""
        rules, regex = rkvdns.prepare_rewrite_rules(
                { b'-eq-':b'=', b'-semi-':b';', b'-dot-':b'.' }
            )

        for k in (b'-eq-', b'-semi-', b'-dot-'):
            self.assertTrue( k in rules, k )
        self.assertEqual( len(rules), 3 )

        parts = regex.split( b'x-eq-x-dot-x-semi-x-eq-xx' )
        self.assertEqual( parts, [b'x', b'-eq-', b'x', b'-dot-', b'x', b'-semi-', b'x', b'-eq-', b'xx'] )
        return

    def test_unicode(self):
        """Things are explicit, but not everything is properly binary."""
        rules, regex = rkvdns.prepare_rewrite_rules(
                { '-eq-':b'=', b'-semi-':';', '-dot-':'.' }
            )

        for k in (b'-eq-', b'-semi-', b'-dot-'):
            self.assertTrue( k in rules, k )
        self.assertEqual( len(rules), 3 )

        parts = regex.split( b'x-eq-x-dot-x-semi-x-eq-xx' )
        self.assertEqual( parts, [b'x', b'-eq-', b'x', b'-dot-', b'x', b'-semi-', b'x', b'-eq-', b'xx'] )
        return

    def test_string(self):
        """Everything in a single string"""
        rules, regex = rkvdns.prepare_rewrite_rules(
                " -eq-:=,-semi- : ; , -dot-: . "
            )

        for k in (b'-eq-', b'-semi-', b'-dot-'):
            self.assertTrue( k in rules, k )
        self.assertEqual( len(rules), 3 )

        parts = regex.split( b'x-eq-x-dot-x-semi-x-eq-xx' )
        self.assertEqual( parts, [b'x', b'-eq-', b'x', b'-dot-', b'x', b'-semi-', b'x', b'-eq-', b'xx'] )
        return
    
    def test_invalid_match_chars(self):
        """Match expressions can't contain regex metacharacters."""
        with self.assertRaises( rkvdns.InvalidRewriteCharactersError ):
            rules, regex = rkvdns.prepare_rewrite_rules(
                    " -eq-:=,-semi- : ; , -.-: . "
                )
        return

if __name__ == '__main__':
    unittest.main(verbosity=2)
