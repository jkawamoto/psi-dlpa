#
# key.py
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
#
"""Public/private keys and encryption/decryption methods for the DLPA service.
"""
# pylint: disable=invalid-name,import-error
from __future__ import absolute_import
from functools import reduce  # pylint: disable=redefined-builtin
import operator
import random

import numpy as np
from dlpa.util import random_m, lcm, gcd, invert, powmod, getprimeover


class PublicKey(object):  # pylint:disable=too-few-public-methods
    """Public key of the DLPA service.

    Args:
      m: Public parameter; :math:`m = pq` where :math:`p` and :math:`q` are
        secret primes.
      g: Representative element of group G.
      glambda: :math:`g^{\\lambda}`,
        where :math:`\\lambda = \\beta {\\rm lcm}(p-1,q-1)` for a random
        :math:`\\beta`.
    """

    def __init__(self, m, g, glambda):
        self.m = m
        self.g = g
        self.glambda = glambda
        self.m2 = m**2

    def encrypt(self, v):
        """Encrypt a given number v.

        The ciphertext of v is defined:

        .. math::

            Enc(v) = g^{v} r^{m} \\mod m^{2}

        Args:
          v: scalar or vector to be encrypted.

        Returns:
          vector of ciphertexts; even if the input is a scalar, one dimension
          vector is returned.
        """
        if not isinstance(v, np.ndarray):
            if not isinstance(v, (tuple, list)):
                v = np.array([v])
            else:
                v = np.array(v)

        r = [random_m(self.m) for _ in range(len(v))]
        m2 = self.m2
        return np.array([
            (powmod(self.g, int(vi), m2) * powmod(ri, self.m, m2)) % m2
            for vi, ri in zip(v, r)
        ])

    def __repr__(self):
        return "PublicKey(m={0}, g={1}, glambda={2})".format(
            hex(self.m)[:8], hex(self.g)[:8], hex(self.glambda)[:8])


class PrivateKey(object):
    """Aggregator's private key of the DLPA service.
    """

    def __init__(self, pk, Lambda):
        self.pk = pk
        self.Lambda = Lambda
        self.a = None
        self.m2 = self.pk.m**2

    def decrypt(self, v):
        """Decrypt a given ciphertext v with given key pair.

        The plain text is defined:

        .. math::

            Dec(v) = \\frac{L(v^{\\lambda})}{L(g^{\\lambda})} \\mod m

        Args:
          v: scalar or vector of ciphertext.

        Returns:
          vector of plain texts; even if the input is a scalar, one dimension
          vector is returned.
        """
        if not isinstance(v, (tuple, list, np.ndarray)):
            v = [v]
        X = [
            (powmod(int(vi), self.Lambda, self.m2) - 1) % self.m2 // self.pk.m
            for vi in v
        ]
        Y = (self.pk.glambda - 1) % self.m2 // self.pk.m

        return np.array([(Xi * invert(Y, self.pk.m)) % self.pk.m for Xi in X])

    def generate_user_keys(self, n):
        """Generate the given number of user's key.
        """
        Lambda_u = []
        a = [random_m(self.pk.m // n) for _ in range(n)]
        b = []
        for _ in range(n - 1):
            Lambda_u.append(random_m(self.pk.m // n))
            b.append(random_m(self.pk.m // n))
        # Sum of Lambda_u must be equal to Lambda.
        Lambda_u.append(self.Lambda - sum(Lambda_u))
        # Sum of a must be remembered.
        self.a = sum(a) % self.m2
        # Sum of b must be equal to 0, i.e. m*2
        b.append(self.m2 - sum(b))

        return [
            ClientKey(self.pk, Lambda_u, au, bu)
            for Lambda_u, au, bu in zip(Lambda_u, a, b)
        ]

    def aggregate_sum(self, ciphertexts):
        """Aggregate a set of ciphertexts for the encrypt-sum algorithm.
        """
        return reduce(operator.mul, ciphertexts) % self.m2

    def decrypt_sum(self, shares):
        """Decrypt a set of decryption shares made in the encrypt-sum algorithm.
        """
        v = reduce(operator.mul, shares) % self.m2
        x = (v - 1) % self.m2 // self.pk.m
        y = (self.pk.glambda - 1) % self.m2 // self.pk.m
        return (x * invert(y, self.pk.m)) % self.pk.m

    def aggregate_sum_squared(self, ciphertexts):
        """First aggregation of a set of decryption shares for Encrypt-Sum-Squared.
        """
        return reduce(operator.mul, ciphertexts) % self.m2

    def aggregate_sum_squared2(self, shares):
        """Second aggregation of a set of decryption shares for Encrypt-Sum-Squared.

        The result :math:`c` is

        .. math::

            c = Enc( (\\sum y_{n})^{2} + \\sum r_{n})

        """
        return (reduce(operator.mul, shares) * self.pk.encrypt(self.a**2)) % self.m2

    def aggregate_noisy_sum(self, C):
        """Aggregate ciphertexts (c1, c2, c3, c4).

        C must be a list of vectors (c1, c2, c3, c4).
        """
        res = []
        for i in range(4):
            res.append(self.aggregate_sum_squared([c[i] for c in C]))
        return res

    def aggregate_noisy_sum2(self, C):
        """Second aggregate ciphertexts (c1, c2, c3, c4, c5).

        C must be a list of vectors (c1, c2, c3, c4, c5).
        """
        res = []
        for i in range(4):
            res.append(self.aggregate_sum_squared2([c[i] for c in C]))
        c5 = self.aggregate_sum([c[4] for c in C])
        return self.aggregate_noisy_sum3(res[0], res[1], res[2], res[3], c5)

    def aggregate_noisy_sum3(  # pylint:disable=too-many-arguments
            self, c1, c2, c3, c4, c5):
        """Aggregate five cipertexts for Encrypt-Noisy-Sum.

        The result :math:`c` is

        .. math::

            c = \\frac{c^{1}c^{2}c^{5}}{c^{3}c^{4}}

        """
        return np.array([
            (c1i * c2i * c5i * invert(int(c3i * c4i), self.m2)) % self.m2
            for c1i, c2i, c3i, c4i, c5i in zip(c1, c2, c3, c4, c5)
        ])


class ClientKey(object):
    """Client's private key of the DLPA service.
    """

    # TODO: ClientKey should hold the cliend ID.
    def __init__(self, pk, Lambda_u, a, b):
        self.pk = pk
        self.Lambda_u = Lambda_u
        self.a = a
        self.b = b
        self.m2 = self.pk.m**2

    def __repr__(self):
        return "ClientKey(pk={0}, lambda={1}, a={2}, b={3})".format(
            self.pk, hex(self.Lambda_u)[:8], hex(self.a)[:8], hex(self.b)[:8])

    def encrypt_sum(self, v, r=None):
        """Encrypt a given value.
        """
        if not isinstance(v, np.ndarray):
            if not isinstance(v, (tuple, list)):
                v = np.array([v])
            else:
                v = np.array(v)
        if r is None:
            r = np.array([random_m(self.pk.m) for _ in range(len(v))])
        e = self.pk.encrypt(v + r)

        def share(c):
            """Compute a decryption share.
            """
            return np.array([
                powmod(int(ci), self.Lambda_u, self.m2) *
                powmod(self.pk.glambda, -int(ri), self.m2)
                for ci, ri in zip(c, r)
            ])

        return e, share

    def encrypt_sum_squared(self, y, r):
        """Encrypt a given number for Encrypt-Sum-Squared.
        """
        if not isinstance(y, np.ndarray):
            if not isinstance(y, (tuple, list)):
                y = np.array([y])
            else:
                y = np.array(y)
        e = self.pk.encrypt(y + self.a + self.b)

        def share(c):
            """Compute the description share associated with this encryption.
            """
            return (np.array([
                powmod(int(ci), int(yi) - self.a + self.b, self.m2)
                for ci, yi in zip(c, y)
            ]) * self.pk.encrypt(r)) % self.m2

        return e, share

    def encrypt_noisy_sum(self, v, sigma, R=None):
        """Encrypt a given number for Encrypt-Noisy-Sum.
        """
        if not isinstance(v, np.ndarray):
            if not isinstance(v, (tuple, list)):
                v = np.array([v])
            else:
                v = np.array(v)
        if not R:
            R = [
                np.array([random_m(self.pk.m) for _ in range(len(v))])
                for _ in range(5)
            ]
        r = (R[0] + R[1] + (self.m2 - R[2]) +
             (self.m2 - R[3]) + R[4]) % self.m2

        enc_y = []
        enc_y_t = []
        for i in range(4):
            y = [self._gauss(0, sigma) for _ in range(len(v))]
            c, t = self.encrypt_sum_squared(y, R[i])
            enc_y.append(c)
            enc_y_t.append(t)

        enc_x, _ = self.encrypt_sum(v, R[4])

        def share(c):
            """Compute the description share associated with this encryption.
            """
            return np.array([
                powmod(int(ci), self.Lambda_u, self.m2) * powmod(
                    self.pk.glambda, -int(ri), self.m2)
                for ci, ri in zip(c, r)
            ])

        return enc_y, enc_y_t, enc_x, share

    def _gauss(self, mean, sigma):
        """Returns a random value under the Gauss distribution in Zm*2.
        """
        y = round(random.gauss(mean, sigma))
        if y < 0:
            y = self.m2 - y
        if y < 0 or y > self.m2:
            y = 0
        return y


def generate_keypair(m_length=2048):
    """Generate a key pair.
    """
    p = q = m = None
    while not m or gcd(m, (p - 1) * (q - 1)) != 1:
        m_len = 0
        while m_len < m_length:
            p = getprimeover(m_length // 2)
            q = getprimeover(m_length // 2)
            if p == q:
                continue
            m = p * q
            m_len = m.bit_length()

    beta = random_m(m)
    Lambda = beta * lcm(p - 1, q - 1)

    a = random_m(m)
    b = random_m(m)
    m2 = m**2

    g = (powmod(1 + m, a, m2) * powmod(b, m, m2)) % m2
    pk = PublicKey(m, g, powmod(g, Lambda, m2))
    sk = PrivateKey(pk, Lambda)
    return sk, pk
