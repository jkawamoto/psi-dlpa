#!/usr/bin/env python3
#
# server.py
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
"""Server of the distributed Laplace Perturbation Algorithm (DLPA) service.
"""
# pylint: disable=import-error,invalid-name
from __future__ import absolute_import, print_function
import argparse
from collections import defaultdict
import functools
import json
import logging
import signal
import sys
import time
import threading

from concurrent import futures
import grpc
import numpy as np

from dlpa.key import generate_keypair
from dlpa import dlpa_pb2
from dlpa import dlpa_pb2_grpc

LOGGER = logging.getLogger("dlpa-server")
"""Logger object.
"""

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

# Minimum time slot -> 5min = 5 * 60 sec.
_TIME_SLOT = 5 * 60


class ProtocolCondition(object):  # pylint: disable=too-many-instance-attributes
    """Maintain protocol conditions and results.
    """

    def __init__(self, aggregator, decrypter, nclient):
        # An aggregation function.
        self.aggregator = aggregator
        # A function decrypting aggregateed decryption shares.
        self.decrypter = decrypter
        # The total number of values which will arrive in each slot.
        self.nclient = nclient
        # Thread condition.
        self.condition = threading.Condition()
        # Map of time_slot->client_id->ciphertext
        self.ciphertexts = defaultdict(dict)
        # Map of time_slot->aggregated_ciphertext
        self.aggregation = {}
        # Condition to access the map of decryption shares.
        self.share_condition = threading.Condition()
        # Map of time_slot->client_id->decryption_share
        self.shares = defaultdict(dict)
        # Map of time_slot->value
        self.results = {}

    def wait_aggregation(self, slot, cid, value):
        """Put a ciphertext and wait an aggregated ciphertext.
        """
        with self.condition:
            self.ciphertexts[slot][cid] = value

            if len(self.ciphertexts[slot]) == self.nclient:
                agg = self.aggregator(self.ciphertexts[slot].values())
                self.aggregation[slot] = agg
                del self.ciphertexts[slot]
                self.condition.notify_all()

            while True:
                if slot in self.aggregation:
                    return self.aggregation[slot]
                else:
                    self.condition.wait()

    def put_share(self, slot, cid, share):
        """Put a decryption share.
        """
        with self.share_condition:
            self.shares[slot][cid] = share
            if len(self.shares[slot]) == self.nclient:
                res = self.decrypter(self.shares[slot].values())
                self.results[slot] = res

                LOGGER.debug("Received(slot: %s, value:%s)", slot, res)
                print(json.dumps(dict(slot=slot, value=res.tolist())), flush=True)

                del self.shares[slot]
                self.share_condition.notify_all()

    def result(self, slot):
        """Wait a result issued in a given slot.
        """
        with self.share_condition:
            while True:
                if slot in self.results:
                    res = self.results[slot]
                    del self.results[slot]
                    return res
                else:
                    self.share_condition.wait()


class EncryptNoisySumCondition(ProtocolCondition):
    """Maintain protocol conditions and results for Encrypt-Noisy-Sum.
    """

    def __init__(self, aggregator, aggregator2, decrypter, nclient):
        super(EncryptNoisySumCondition, self).__init__(
            aggregator, decrypter, nclient)

        # An aggregation function.
        self.aggregator2 = aggregator2
        # Thread condition.
        self.condition2 = threading.Condition()
        # Map of time_slot->client_id->ciphertext
        self.ciphertexts2 = defaultdict(dict)
        # Map of time_slot->aggregated_ciphertext
        self.aggregation2 = {}

    def wait_aggregation2(self, slot, cid, value):
        """Put a ciphertext and wait an aggregated ciphertext.
        """
        with self.condition2:
            self.ciphertexts2[slot][cid] = value

            if len(self.ciphertexts2[slot]) == self.nclient:
                agg = self.aggregator2(self.ciphertexts2[slot].values())
                self.aggregation2[slot] = agg
                del self.ciphertexts2[slot]
                self.condition2.notify_all()

            while True:
                if slot in self.aggregation2:
                    return self.aggregation2[slot]
                else:
                    self.condition2.wait()


class DLPAServicer(dlpa_pb2_grpc.DLPAServicer):
    """DLPAServicer implements DLPAServicer defined in the proto file.

    Args:
      nclient: The number of client connecting this server.
      m_length: Security parameter.
      span: Second of one time slot.
    """

    def __init__(self, nclient=20, m_length=2048, span=_TIME_SLOT):
        self.nclient = nclient
        self.sk, self.pk = generate_keypair(m_length)
        self.cks = self.sk.generate_user_keys(nclient)
        self.span = span

        # Map of target -> ProtocolCondition for Encrypt-Sum.
        self.encrypt_sum = defaultdict(functools.partial(
            ProtocolCondition,
            aggregator=self.sk.aggregate_sum,
            decrypter=self.sk.decrypt_sum,
            nclient=nclient))

        # Map of target -> ProtocolCondition for Encrypt-Sum-Squared.
        self.encrypt_sum_squared = defaultdict(functools.partial(
            ProtocolCondition,
            aggregator=self.sk.aggregate_sum_squared,
            decrypter=self.sk.aggregate_sum_squared2,
            nclient=nclient))

        # ProtocolCondition for Encrypt-Noisy-Sum.
        self.encrypt_noisy_sum = EncryptNoisySumCondition(
            aggregator=self.sk.aggregate_noisy_sum,
            aggregator2=self.sk.aggregate_noisy_sum2,
            decrypter=self.sk.decrypt_sum,
            nclient=nclient)

    def __repr__(self):
        return "DLPAServicer(nclient={0}, pk={1}, sk={2})".format(
            self.nclient, self.pk, self.sk)

    def GetKey(self, request, context):
        """GetKey takes a client ID and returns a client key.
        """
        try:
            ck = self.cks[request.id]

        except IndexError:
            context.cancel()
            return dlpa_pb2.ClientKey()

        else:
            return dlpa_pb2.ClientKey(
                lambda_u=str(ck.Lambda_u),
                a=str(ck.a),
                b=str(ck.b),
                public_key=dlpa_pb2.PublicKey(
                    m=str(self.pk.m),
                    g=str(self.pk.g),
                    glambda=str(self.pk.glambda)
                )
            )

    def aggregate_ciphertexts(self, conditon, request, _context):
        """Put a cipertext and wait to aggregate them with a given context.
        """
        cid = request.id
        slot = request.time // self.span
        value = np.array([int(v) for v in request.value])
        target = request.target

        c = conditon[target].wait_aggregation(slot, cid, value)
        return dlpa_pb2.Ciphertext(id=0, time=slot, value=[str(v) for v in c])

    @staticmethod
    def aggregate_shares(condition, request, _context):
        """Put a decryption share; if all shares are put, computes the result.
        """
        cid = request.id
        slot = request.slot
        share = np.array([int(s) for s in request.share])
        target = request.target

        condition[target].put_share(slot, cid, share)
        return dlpa_pb2.NoResponse()

    def PutEncryptSum(self, request, context):
        """Takes a cipertext for encrypt-sum and returns aggregated value.
        """
        return self.aggregate_ciphertexts(self.encrypt_sum, request, context)

    def PutEncryptSumShare(self, request, context):
        """Takes a decryption share; and decrypts them when receives all shares.
        """
        return self.aggregate_shares(self.encrypt_sum, request, context)

    def PutEncryptSumSquared(self, request, context):
        """Takes a cipertext for encrypt-sum-squared and returns aggregated value.
        """
        return self.aggregate_ciphertexts(
            self.encrypt_sum_squared, request, context)

    def PutEncryptSumSquaredShare(self, request, context):
        """Takes a decryption share; and decrypts them when receives all shares.
        """
        return self.aggregate_shares(self.encrypt_sum_squared, request, context)

    def PutEncryptNoisySum(self, request, context):
        """Takes a cipertext for encrypt-noisy-sum and returns aggregated value.
        """
        cid = request.id
        slot = request.time // self.span
        # c5 is not used in this phase.
        value = [
            np.array([int(v) for v in request.value.c1]),
            np.array([int(v) for v in request.value.c2]),
            np.array([int(v) for v in request.value.c3]),
            np.array([int(v) for v in request.value.c4])
        ]
        _ = context

        c = self.encrypt_noisy_sum.wait_aggregation(slot, cid, value)
        return dlpa_pb2.EncryptNoisySumCiphertexts(
            id=0,
            time=slot,
            value=dlpa_pb2.CiphertextVector(
                c1=[str(v) for v in c[0]],
                c2=[str(v) for v in c[1]],
                c3=[str(v) for v in c[2]],
                c4=[str(v) for v in c[3]]
            ))

    def PutEncryptNoisySumShare(self, request, context):
        """Takes a cipertext for encrypt-noisy-sum and returns 2nd aggregated value.
        """
        cid = request.id
        slot = request.time
        value = [
            np.array([int(v) for v in request.value.c1]),
            np.array([int(v) for v in request.value.c2]),
            np.array([int(v) for v in request.value.c3]),
            np.array([int(v) for v in request.value.c4]),
            np.array([int(v) for v in request.value.c5])
        ]
        _ = context

        c = self.encrypt_noisy_sum.wait_aggregation2(slot, cid, value)
        return dlpa_pb2.Ciphertext(id=0, time=slot, value=[str(v) for v in c])

    def PutEncryptNoisySumLastShare(self, request, context):
        """Takes a decryption share; and decrypts them when receives all shares.
        """
        cid = request.id
        slot = request.slot
        share = np.array([int(s) for s in request.share])
        _ = context

        self.encrypt_noisy_sum.put_share(slot, cid, share)
        return dlpa_pb2.NoResponse()


def server(port=50051, max_workers=10, servicer=None, **kwargs):
    """Create a new server listening a given port.

    This function starts the created server; but caller is responsible for stop
    it.

    One of the servicer argument or the pair of the nclient and m_length
    arguments must be given.

    Args:
      port: Port number the created server listen.
      max_workers: The number of maximum service workers.
      servicer: Instance :class:`DLPAServicer`.
      nclient: The number of client connecting this server.
      m_length: Security parameter.

    Returns:
      Server object which has stop method. Callers are responsible for calling
      this stop function to stop the created server.
    """
    if not servicer:
        LOGGER.info("Creating DLPAServicer.")
        servicer = DLPAServicer(**kwargs)
        LOGGER.info("DLPAServicer is created.")

    s = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    dlpa_pb2_grpc.add_DLPAServicer_to_server(servicer, s)
    s.add_insecure_port("[::]:{0}".format(port))
    LOGGER.info("Starting a server listening port %d", port)
    s.start()
    return s


def main():
    """The main function.
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port", required=True, type=int,
        help="Listening port number.")
    parser.add_argument(
        "--clients", required=True, type=int, dest="nclient",
        help="The number of clients.")
    parser.add_argument(
        "--max-workers", default=10, type=int, dest="max_workers",
        help="The maximum number of workers (default: 10).")
    parser.add_argument(
        "--key-length", default=2048, type=int, dest="m_length",
        help="Bit length of the secret key (default: 2048).")
    parser.add_argument(
        "--time-span", default=_TIME_SLOT, type=int, dest="span",
        help="Second of one time slot."
    )

    s = server(**vars(parser.parse_args()))

    def signal_handler():
        """Catch a signal and stop the server.
        """
        LOGGER.info("Stopping the server.")
        s.stop(0)
        logging.shutdown()

    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        LOGGER.info("Canceled.")
    except Exception as e:  # pylint: disable=broad-except
        LOGGER.exception("Untracked exception occurred: %s", e.message)
    finally:
        LOGGER.info("Stopping the server.")
        s.stop(0)
        logging.shutdown()


if __name__ == "__main__":
    main()
