#
# rpc_test.py
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
"""Unittest for rpc client/server.
"""
# pylint: disable=import-error,invalid-name,wrong-import-position
from __future__ import print_function
import random
import sys
import threading
import unittest

import numpy as np

from dlpa.util import random_m
from dlpa import DLPAClient, DLPAServicer, server


class BaseTestCase(unittest.TestCase):
    """Base test case which prepares a pair of rpc client/server.
    """

    def setUp(self):
        """Set up a pair of rpc client/server.
        """
        self.servicer = DLPAServicer(nclient=2, m_length=128)
        self.port = random.randint(40051, 59999)
        self.server = server(self.port, servicer=self.servicer)

    def tearDown(self):
        """Stop the rpc server.
        """
        self.server.stop(None)


class TestGetKey(BaseTestCase):
    """Test case to obtain a client key.
    """

    def test_get_key(self):
        """Test GetKey method.
        """
        c = DLPAClient(port=self.port)
        ck = c.get_key(1)

        self.assertEqual(ck.pk.m, self.servicer.pk.m)
        self.assertEqual(ck.pk.g, self.servicer.pk.g)
        self.assertEqual(ck.pk.glambda, self.servicer.pk.glambda)

        self.assertEqual(ck.Lambda_u, self.servicer.cks[1].Lambda_u)
        self.assertEqual(ck.a, self.servicer.cks[1].a)
        self.assertEqual(ck.b, self.servicer.cks[1].b)

    def test_get_key_with_invalid_user_id(self):
        """Test GetKey method with an invalid user ID.
        """
        c = DLPAClient(port=self.port)
        with self.assertRaises(RuntimeError):
            _ = c.get_key(10)


class TestEncryptSum(BaseTestCase):
    """Test case for Encrypt-Sum.
    """

    def test(self):
        """Test Encrypt-Sum protocol with a set of simple values.
        """
        clients = [DLPAClient(port=self.port) for _ in range(2)]
        cks = [c.get_key(i) for i, c in enumerate(clients)]
        slots = []

        def requester(c, ck, client_id, value):
            """Send a request in another thread.
            """
            slot = c.encrypt_sum(ck, client_id, value, target="test")
            slots.append(slot)

        threads = []
        for i, (c, key) in enumerate(zip(clients, cks)):
            # value = i + 1.
            t = threading.Thread(target=requester, args=(c, key, i, i + 1))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], slots[1])
        self.assertIn("test", self.servicer.encrypt_sum)
        self.assertEqual(self.servicer.encrypt_sum["test"].result(slots[0]), 3)


class TestEncryptSumSquared(BaseTestCase):
    """Test case for Encrypt-Sum-Squared.
    """

    def test(self):
        """Test Encrypt-Sum-Squared.
        """
        R = [random_m(self.servicer.pk.m) for _ in range(2)]
        self.run_encrypt_sum_squad(R)

    def test_without_randomness(self):
        """Test Encrypt-Sum-Squared without randomness.
        """
        R = [0 for _ in range(2)]
        self.run_encrypt_sum_squad(R)

    def run_encrypt_sum_squad(self, R):  # pylint:disable=too-many-locals
        """Execute Encrypt-Sum-Squad with a given set of random values.
        """
        clients = [DLPAClient(port=self.port) for _ in range(2)]
        cks = [c.get_key(i) for i, c in enumerate(clients)]
        slots = []

        def requester(c, ck, client_id, value, rand):
            """Send a request in another thread.
            """
            slot = c.encrypt_sum_squared(
                ck, client_id, value, rand, target="test")
            slots.append(slot)

        threads = []
        for i, (c, key, rand) in enumerate(zip(clients, cks, R)):
            # value = i + 1.
            t = threading.Thread(
                target=requester, args=(c, key, i, i + 1, rand))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], slots[1])
        self.assertIn("test", self.servicer.encrypt_sum_squared)
        res = self.servicer.encrypt_sum_squared["test"].result(slots[0])
        v = self.servicer.sk.decrypt(res)
        sum_of_values = (1 + 2) * 2 // 2
        self.assertEqual(v, (sum_of_values**2 + sum(R)) % self.servicer.pk.m)


class TestEncryptNoisySum(BaseTestCase):
    """Test case for Encrypt-Noisy-Sum.
    """

    def test(self):
        """Test Encrypt-Noisy-Sum.
        """
        clients = [DLPAClient(port=self.port) for _ in range(2)]
        cks = [c.get_key(i) for i, c in enumerate(clients)]
        slots = []

        def requester(c, ck, client_id, value):
            """Send a request in another thread.
            """
            slot = c.encrypt_noisy_sum(
                ck, client_id, value, 0.25)
            slots.append(slot)

        threads = []
        for i, (c, key) in enumerate(zip(clients, cks)):
            # value = i + 1.
            t = threading.Thread(
                target=requester, args=(c, key, i, i + 1))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], slots[1])
        res = self.servicer.encrypt_noisy_sum.result(slots[0])
        sum_of_values = (1 + 2) * 2 // 2
        print("Correct: {1}, Noised: {0}".format(res, sum_of_values))

    def test_without_noise(self):
        """Test Encrypt-Noisy-Sum without adding noises.
        """
        clients = [DLPAClient(port=self.port) for _ in range(2)]
        cks = [c.get_key(i) for i, c in enumerate(clients)]
        slots = []

        def requester(c, ck, client_id, value):
            """Send a request in another thread.
            """
            slot = c.encrypt_noisy_sum(
                ck, client_id, value, 0)
            slots.append(slot)

        threads = []
        for i, (c, key) in enumerate(zip(clients, cks)):
            # value = i + 1.
            t = threading.Thread(
                target=requester, args=(c, key, i, i + 1))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], slots[1])
        res = self.servicer.encrypt_noisy_sum.result(slots[0])
        sum_of_values = (1 + 2) * 2 // 2
        self.assertEqual(res, sum_of_values)

    def test_without_randomness(self):
        """Test Encrypt-Noisy-Sum without randomness.
        """
        clients = [DLPAClient(port=self.port) for _ in range(2)]
        cks = [c.get_key(i) for i, c in enumerate(clients)]
        slots = []

        def requester(c, ck, client_id, value):
            """Send a request in another thread.
            """
            slot = c.encrypt_noisy_sum(
                ck,
                client_id,
                value,
                0,
                rand=[np.array([0]) for _ in range(5)])
            slots.append(slot)

        threads = []
        for i, (c, key) in enumerate(zip(clients, cks)):
            # value = i + 1.
            t = threading.Thread(
                target=requester, args=(c, key, i, i + 1))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.assertEqual(len(slots), 2)
        self.assertEqual(slots[0], slots[1])
        res = self.servicer.encrypt_noisy_sum.result(slots[0])
        sum_of_values = (1 + 2) * 2 // 2
        self.assertEqual(res, sum_of_values)


if __name__ == "__main__":
    unittest.main()
