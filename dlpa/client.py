#
# client.py
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
"""Client of the distributed Laplace Perturbation Algorithm (DLPA) service.
"""
# pylint: disable=invalid-name,import-error,too-many-arguments
from __future__ import absolute_import, print_function
import calendar
import datetime

import grpc
import numpy as np

from dlpa.key import PublicKey, ClientKey
from dlpa import dlpa_pb2
from dlpa import dlpa_pb2_grpc


class DLPAClient(object):
    """DLPAClient provides methods the DLPA service defines.

    See `dlpa.proto` for more information about DLPA service.

    Args:
      host: Address of a DLPA server to connect.
      port: Port number of the DLPA server to connect.
    """

    def __init__(self, host="localhost", port=50051):
        channel = grpc.insecure_channel(
            "{host}:{port}".format(host=host, port=port))
        self.stub = dlpa_pb2_grpc.DLPAStub(channel)

    def get_key(self, client_id):
        """Request a client key associated with a given client id.

        Args:
          client_id: Given ID of this client.

        Returns:
          a client key object.

        Raises:
          RuntimeError: when the GetKey protocol ends with errors.
        """
        try:
            res = self.stub.GetKey(dlpa_pb2.GetKeyRequest(id=client_id))

        except Exception as e:  # pylint: disable=broad-except
            raise RuntimeError("Cannot get keys.", e)

        else:
            pk = PublicKey(
                m=int(res.public_key.m),
                g=int(res.public_key.g),
                glambda=int(res.public_key.glambda)
            )
            ck = ClientKey(
                pk=pk, Lambda_u=int(res.lambda_u), a=int(res.a), b=int(res.b))
            return ck

    def encrypt_sum(self, ck, client_id, value, rand=None, target=None):
        """Run Encrypt-Sum protocol to send a given value.

        This method returns a time slot with which the given value is associated.

        Args:
          ck: Client key.
          client_id: Client ID.
          value: Scalar or vector to be sent to the server by Encrypt-Sum
            protocol.
          rand: Use specific values as random values used in the protocol.
            If set None, by default, use actual random values.
          target: If given, store the value with a specific name in the server.

        Returns:
          Time slot number attached to the given value.
        """
        ciphertext, transform = ck.encrypt_sum(value, rand)
        unix = self.now()

        # Send the encrypted value and receive an aggregated ciphertext.
        res = self.stub.PutEncryptSum(dlpa_pb2.Ciphertext(
            time=unix,
            id=client_id,
            value=[str(c) for c in ciphertext],
            target=target))

        # Compute the decryption share and send it.
        share = transform(np.array([int(v) for v in res.value]))
        self.stub.PutEncryptSumShare(dlpa_pb2.DecryptionShare(
            slot=res.time,
            id=client_id,
            share=[str(s) for s in share],
            target=target))

        return res.time

    def encrypt_sum_squared(self, ck, client_id, value, rand, target=None):
        """Run Encrypt-Sum-Squared protocol to send a given value.

        This method returns a time slot with which the given value is associated.

        Args:
          ck: Client key.
          client_id: Client ID.
          value: Scalar or vector to be sent to the server by
            Encrypt-Sum-Squared protocol.
          rand: Use specific values as random values used in the protocol.
          target: If given store the value with a specific name in the server.

        Returns:
          Time slot number attached to the given value.
        """
        ciphertext, transform = ck.encrypt_sum_squared(value, rand)
        unix = self.now()

        # Send the encrypted value and receive an aggregated ciphertext.
        res = self.stub.PutEncryptSumSquared(dlpa_pb2.Ciphertext(
            time=unix,
            id=client_id,
            value=[str(c) for c in ciphertext],
            target=target))

        # Compute the decryption share and send it.
        share = transform(np.array([int(v) for v in res.value]))
        self.stub.PutEncryptSumSquaredShare(dlpa_pb2.DecryptionShare(
            slot=res.time,
            id=client_id,
            share=[str(s) for s in share],
            target=target))

        return res.time

    def encrypt_noisy_sum(self, ck, client_id, value, epsilon, rand=None):
        """Run Encrypt-Noisy-Sum protocol.

        Args:
          ck: Client key.
          client_id: Client ID.
          value: Scalar or vector to be sent to the server by Encrypt-Sum
            protocol.
          epsilon: Parameter to generate Laplace noises.
          rand: Use specific values as random values used in the protocol.
            If set None, by default, use actual random values.

        Returns:
          Time slot number attached to the given value.
        """
        y, y_t, x, t = ck.encrypt_noisy_sum(value, epsilon, R=rand)
        unix = self.now()

        req = dlpa_pb2.EncryptNoisySumCiphertexts(
            time=unix,
            id=client_id,
            value=dlpa_pb2.CiphertextVector(
                c1=[str(v) for v in y[0]],
                c2=[str(v) for v in y[1]],
                c3=[str(v) for v in y[2]],
                c4=[str(v) for v in y[3]]))

        aggregation = self.stub.PutEncryptNoisySum(req)
        req2 = dlpa_pb2.EncryptNoisySumCiphertexts(
            time=aggregation.time,
            id=client_id,
            value=dlpa_pb2.CiphertextVector(
                c1=[
                    str(v) for v in y_t[0](
                        np.array([int(a) for a in aggregation.value.c1]))
                ],
                c2=[
                    str(v) for v in y_t[1](
                        np.array([int(a) for a in aggregation.value.c2]))
                ],
                c3=[
                    str(v) for v in y_t[2](
                        np.array([int(a) for a in aggregation.value.c3]))
                ],
                c4=[
                    str(v) for v in y_t[3](
                        np.array([int(a) for a in aggregation.value.c4]))
                ],
                c5=[str(v) for v in x]
            ))

        res = self.stub.PutEncryptNoisySumShare(req2)
        share = t(np.array([int(v) for v in res.value]))
        self.stub.PutEncryptNoisySumLastShare(dlpa_pb2.DecryptionShare(
            slot=res.time,
            id=client_id,
            share=[str(s) for s in share]))

        return res.time

    @staticmethod
    def now():
        """Returns a UNIX time of now.
        """
        now = datetime.datetime.utcnow()
        return calendar.timegm(now.utctimetuple())
