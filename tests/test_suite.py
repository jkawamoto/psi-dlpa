#
# test_suite.py
#
# Copyright (c) 2017 Junpei Kawamoto
#
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Define the test suite.
"""
# pylint: disable=import-error
import logging
import sys
import unittest

from tests import dlpa_test
from tests import rpc_test


def suite():
    """Return a test suite.
    """
    logging.basicConfig(level=logging.INFO)
    loader = unittest.TestLoader()
    res = unittest.TestSuite()
    res.addTest(loader.loadTestsFromModule(dlpa_test))
    res.addTest(loader.loadTestsFromModule(rpc_test))
    return res


def main():
    """The main function.

    Returns:
      exit code.
    """
    try:
        res = unittest.TextTestRunner(verbosity=2).run(suite())
    except KeyboardInterrupt:
        return -1
    else:
        return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
