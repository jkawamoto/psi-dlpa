#
# dlpa_test.py
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
"""Unit test of encryption and decryption defined in dlpa package.
"""
# pylint: disable=import-error,invalid-name,too-many-locals
from __future__ import division
from functools import reduce  # pylint: disable=redefined-builtin,unused-import
import logging
import random
import sys
import unittest

import numpy as np

from dlpa.util import powmod, random_m  # pylint:disable=wrong-import-position
from dlpa.key import generate_keypair  # pylint:disable=wrong-import-position


class TestKeyGeneration(unittest.TestCase):
    """Test case for generated a key pair.
    """

    def setUp(self):
        """Generate a key pair for each test.
        """
        self.sk, self.pk = generate_keypair(128)

    def test_propertyof_m_and_lambda(self):
        """Test :math:`b^{m\\lambda} \\equiv 1 \\mod m^{2}`.
        """
        b = random_m(self.pk.m)
        self.assertEqual(
            powmod(b, self.pk.m * self.sk.Lambda, self.pk.m**2), 1)

    def test_glambda(self):
        """Test :math:`(g^{\\lambda})^{m} \\equiv 1 \\mod m^{2}`.
        """
        self.assertEqual(powmod(self.pk.glambda, self.pk.m, self.pk.m**2), 1)

    def test_g(self):
        """Test :math:`g^{\\lambda}`.
        """
        self.assertEqual(
            powmod(self.pk.g, self.sk.Lambda, self.pk.m**2), self.pk.glambda)

    def test_non_zero(self):
        """Test any values in a key pair are not 0.
        """
        self.assertNotEqual(self.pk.m, 0)
        self.assertNotEqual(self.pk.g, 0)
        self.assertNotEqual(self.pk.glambda, 0)
        self.assertNotEqual(self.sk.Lambda, 0)


class TestPaillierCryptoSystem(unittest.TestCase):
    """Test case of the basic Paillier crypto system.
    """

    def setUp(self):
        """Generate a key pair for each test.
        """
        self.sk, self.pk = generate_keypair(128)

    def test_encryption(self):
        """Test Dec(Enc(v)) = v.
        """
        c = self.pk.encrypt(20)
        self.assertNotEqual(c[0], 0)
        v = self.sk.decrypt(c)
        self.assertEqual(v[0], 20)

    def test_encrypt_vector(self):
        """Test Dec(Enc(v)) = v for a vector v.
        """
        data = list(range(1, 21))
        c = self.pk.encrypt(data)
        res = self.sk.decrypt(c)
        for d, v in zip(data, res):
            self.assertEqual(d, v)

    def test_sum(self):
        """Test Dec(Enc(a) * Enc(b)) = a + b.
        """
        a, b = 20, 31
        c1 = self.pk.encrypt(a)
        c2 = self.pk.encrypt(b)
        self.assertNotEqual(c1[0], 0)
        self.assertNotEqual(c2[0], 0)

        v = self.sk.decrypt(c1 * c2)
        self.assertEqual(v, a + b)

    def test_sum_vector(self):
        """Test Dec(Enc(a) * Enc(b)) = a + b, for vectors a and b.
        """
        a = [random.randint(1, 20) for _ in range(20)]
        b = [random.randint(1, 20) for _ in range(20)]
        c1 = self.pk.encrypt(a)
        c2 = self.pk.encrypt(b)
        res = self.sk.decrypt(c1 * c2)
        for v, x, y in zip(res, a, b):
            self.assertEqual(v, x + y)


class BaseTestCase(unittest.TestCase):
    """Base test case providing keys.
    """

    def setUp(self):
        """Generate a key pair and client keys.
        """
        self.sk, self.pk = generate_keypair(128)
        self.cks = self.sk.generate_user_keys(20)


class TestEncryptSum(BaseTestCase):
    """Test case for Encrypt-Sum.
    """

    def test(self):
        """Run Encrypt-Sum algorithm.
        """
        C = []
        T = []
        for i, ck in enumerate(self.cks):
            c, t = ck.encrypt_sum(i + 1)
            C.append(c)
            T.append(t)

        # Aggregate ciphertexts.
        c = self.sk.aggregate_sum(C)

        # Compute decryption shares.
        shares = [t(c) for t in T]

        v = self.sk.decrypt_sum(shares)
        self.assertEqual(v, (1 + 20) * 20 // 2)

    def test_vector_without_randomnesss(self):
        """Run Encrypt-Sum algorithm for vectors whiteout randomness.
        """
        data = [
            np.array([random.randint(1, 1024) for _ in range(20)])
            for _ in range(len(self.cks))
        ]
        C = []
        T = []
        for d, ck in zip(data, self.cks):
            c, t = ck.encrypt_sum(d, [0] * len(d))
            C.append(c)
            T.append(t)

        # Aggregate ciphertexts.
        c = self.sk.aggregate_sum(C)
        self.assertEqual(len(c), len(data[0]))

        # Compute decryption shares.
        shares = [t(c) for t in T]

        res = self.sk.decrypt_sum(shares)
        self.assertEqual(len(res), len(data[0]))
        for v, d in zip(res, sum(data)):
            self.assertEqual(v, d)

    def test_vector(self):
        """Run Encrypt-Sum algorithm with vectors.
        """
        data = [
            np.array([random.randint(1, 1024) for _ in range(20)])
            for _ in range(len(self.cks))
        ]
        C = []
        T = []
        for d, ck in zip(data, self.cks):
            c, t = ck.encrypt_sum(d)
            C.append(c)
            T.append(t)

        # Aggregate ciphertexts.
        c = self.sk.aggregate_sum(C)
        self.assertEqual(len(c), len(data[0]))

        # Compute decryption shares.
        shares = [t(c) for t in T]

        res = self.sk.decrypt_sum(shares)
        self.assertEqual(len(res), len(data[0]))
        for v, d in zip(res, sum(data)):
            self.assertEqual(v, d)


class TestEncryptSumSquared(BaseTestCase):
    """Test case for Encrypt-Sum-Squared.
    """

    def test_private_keys(self):
        """Test the summation of a and b.
        """
        m2 = self.pk.m**2
        a = sum([c.a for c in self.cks]) % m2
        self.assertEqual(a, self.sk.a)

        b = sum([c.b for c in self.cks]) % m2
        self.assertEqual(b, 0)

    def test(self):
        """Test Encrypt-Sum-Squared.
        """
        R = [random_m(self.pk.m) for _ in range(len(self.cks))]
        self.run_encrypt_sum_squad(R)

    def test_without_randomness(self):
        """Test Encrypt-Sum-Squared without randomness.
        """
        R = [0 for _ in range(len(self.cks))]
        self.run_encrypt_sum_squad(R)

    def run_encrypt_sum_squad(self, R):
        """Execute Encrypt-Sum-Squad with a given set of random values.
        """
        C = []
        T = []
        for i, (ck, r) in enumerate(zip(self.cks, R)):
            cu, t = ck.encrypt_sum_squared(i + 1, r)
            C.append(cu)
            T.append(t)

        c = self.sk.aggregate_sum_squared(C)
        cp = self.sk.aggregate_sum_squared2([t(c) for t in T])
        self.assertNotEqual(cp, 0)

        res = self.sk.decrypt(cp)
        sum_of_values = (1 + len(self.cks)) * len(self.cks) // 2
        self.assertEqual(res, (sum_of_values**2 + sum(R)) % self.pk.m)

    def test_with_zeros(self):
        """Test Encrypt-Sum-Squared with 0.
        """
        R = [random_m(self.pk.m) for _ in range(len(self.cks))]
        C = []
        T = []
        for ck, r in zip(self.cks, R):
            cu, t = ck.encrypt_sum_squared(0, r)
            C.append(cu)
            T.append(t)

        c = self.sk.aggregate_sum_squared(C)
        cp = self.sk.aggregate_sum_squared2([t(c) for t in T])

        res = self.sk.decrypt(cp)
        self.assertEqual(res, sum(R) % self.pk.m)

    def test_vector(self):
        """Test Encrypt-Sum-Squad with vectors.
        """
        data = [
            np.array([random_m(self.pk.m) for _ in range(20)])
            for _ in range(len(self.cks))
        ]
        R = [
            np.array([random_m(self.pk.m) for _ in range(20)])
            for _ in range(len(self.cks))
        ]

        C = []
        T = []
        for ck, d, r in zip(self.cks, data, R):
            cu, t = ck.encrypt_sum_squared(d, r)
            C.append(cu)
            T.append(t)

        c = self.sk.aggregate_sum_squared(C)
        cp = self.sk.aggregate_sum_squared2([t(c) for t in T])

        res = self.sk.decrypt(cp)
        sum_of_values = sum(data)

        ans = (sum_of_values**2 + sum(R)) % self.pk.m
        for v, d in zip(res, ans):
            self.assertEqual(v, d)


class TestEncryptNoisySum(BaseTestCase):
    """Test case for Encrypt-Noisy-Sum.
    """

    def test(self):
        """Test the protocol.
        """
        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for i, c in enumerate(self.cks):
            y, y_t, x, t = c.encrypt_noisy_sum(i + 1, 0.01)
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        v = self.sk.decrypt_sum([t(cp) for t in T])

        self.assertNotEqual(v, 0)

    def test_without_noise(self):
        """Test Encrypt-Noisy-Sum without noises.
        """
        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for i, c in enumerate(self.cks):
            y, y_t, x, t = c.encrypt_noisy_sum(i + 1, 0)
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        v = self.sk.decrypt_sum([t(cp) for t in T])

        self.assertEqual(v, (1 + 20) * 20 // 2)

    def test_without_randomness(self):
        """Test Encrypt-Noisy-Sum without random values.
        """
        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for i, c in enumerate(self.cks):
            y, y_t, x, t = c.encrypt_noisy_sum(
                i + 1, 0, R=[np.array([0]) for _ in range(5)])
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)
        ans = (1 + len(self.cks)) * len(self.cks) // 2

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        v = self.sk.decrypt_sum([t(cp) for t in T])

        self.assertEqual(v, ans)

    def test_vector_without_noise(self):
        """Test Encrypt-Noisy-Sum for vectors without noises.
        """
        data = [
            np.array([random_m(self.pk.m) for _ in range(20)])
            for _ in range(len(self.cks))
        ]

        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for c, v in zip(self.cks, data):
            y, y_t, x, t = c.encrypt_noisy_sum(v, 0)
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        res = self.sk.decrypt_sum([t(cp) for t in T])

        for v, d in zip(res, sum(data) % self.pk.m):
            self.assertEqual(v, d)

    def test_vector_without_randomness(self):
        """Test Encrypt-Noisy-Sum for vectors without randomness.
        """
        data = [
            np.array([random_m(self.pk.m) for _ in range(20)])
            for _ in range(len(self.cks))
        ]

        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for c, v in zip(self.cks, data):
            R = [np.array([0 for _ in range(len(v))]) for _ in range(5)]
            y, y_t, x, t = c.encrypt_noisy_sum(v, 0, R)
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        res = self.sk.decrypt_sum([t(cp) for t in T])

        for v, d in zip(res, sum(data) % self.pk.m):
            self.assertEqual(v, d)

    def test_zero_vector_without_randomness(self):
        """Test Encrypt-Noisy-Sum for zero vectors without randomness.
        """
        data = [
            np.array([0 for _ in range(20)])
            for _ in range(len(self.cks))
        ]

        Y = []
        Yt = []
        X = []
        T = []
        logging.info("Step1: calling encrypt_noisy_sum")
        for c, v in zip(self.cks, data):
            R = [np.array([0 for _ in range(len(v))]) for _ in range(5)]
            y, y_t, x, t = c.encrypt_noisy_sum(v, 0, R)
            Y.append(y)
            Yt.append(y_t)
            X.append(x)
            T.append(t)

        logging.info("Step2: aggregate_noisy_sum")
        cy = self.sk.aggregate_noisy_sum(Y)

        logging.info("Step3: aggregate_noisy_sum2")
        cp = self.sk.aggregate_noisy_sum2([
            [t[i](c) for i, c in enumerate(cy)] + [x] for t, x in zip(Yt, X)
        ])

        logging.info("Step4: decrypt_sum")
        res = self.sk.decrypt_sum([t(cp) for t in T])

        self.assertEqual(len(res), len(data[0]))
        for v in res:
            self.assertEqual(v, 0)

if __name__ == "__main__":
    unittest.main()
