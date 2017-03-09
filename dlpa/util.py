#
# util.py
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
"""Provides helper functions for the DLPA service.
"""
# pylint: disable=invalid-name
from __future__ import absolute_import
import os
import random


def gcd(x, y):
    """Return the G.C.D.

    This function implements the Euclidian algorithm
    to find G.C.D. of two numbers
    """
    while y:
        x, y = y, x % y
    return x


def lcm(x, y):
    """Return the L.C.M.

    This function takes two
    integers and returns the L.C.M.
    """
    return (x * y) // gcd(x, y)


def phi(n):
    """Euler's totient function.
    """
    amount = 0
    for k in range(1, n + 1):
        if gcd(n, k) == 1:
            amount += 1
    return amount


def has_inverse(v, m):
    """Return True if the given v has an inverse in mod m.
    """
    try:
        # print(v, invert(v, m), m)
        return invert(v, m) < m
    except ValueError:
        return False
    except ZeroDivisionError:
        return False


def random_m(m):
    """Random value from Zm*.
    """
    r = 0
    while not has_inverse(r, m):
        r = random.randint(1, m - 1)
    return r

#
# The following functions are made by
#   Data61 | CSIRO <brian.thorne@data61.csiro.au>,
# and released under the GPLv3.
# You can find the original source code in
# https://github.com/n1analytics/python-paillier/blob/master/phe/util.py
#
# pylint: disable=no-member
try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

try:
    from Crypto.Util import number
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# GMP's powmod has greater overhead than Python's pow, but is faster.
# From a quick experiment on our machine, this seems to be the break even:
_USE_MOD_FROM_GMP_SIZE = (1 << (8 * 2))


def powmod(a, b, c):
    """
    Uses GMP, if available, to do a^b mod c where a, b, c
    are integers.
    :return int: (a ** b) % c
    """
    if a == 1:
        return 1
    if not HAVE_GMP or max(a, b, c) < _USE_MOD_FROM_GMP_SIZE:
        return pow(a, b, c)
    else:
        return int(gmpy2.powmod(a, b, c))


def invert(a, b):
    """
    The multiplicitive inverse of a in the integers modulo b.
    :return int: x, where a * x == 1 mod b
    """
    if HAVE_GMP:
        return int(gmpy2.invert(a, b))
    else:
        # http://code.activestate.com/recipes/576737-inverse-modulo-p/
        for d in range(1, b):
            r = (d * a) % b
            if r == 1:
                break
        else:
            raise ValueError('%d has no inverse mod %d' % (a, b))
        return d  # pylint: disable=undefined-loop-variable


def getprimeover(N):
    """Return a random N-bit prime number using the System's best
    Cryptographic random source.
    Use GMP if available, otherwise fallback to PyCrypto
    """
    if HAVE_GMP:
        randfunc = random.SystemRandom()
        r = gmpy2.mpz(randfunc.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))
    elif HAVE_CRYPTO:
        return number.getPrime(N, os.urandom)
    else:
        raise NotImplementedError("No pure python implementation sorry")
