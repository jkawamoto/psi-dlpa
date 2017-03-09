:description: Client and server applications providing Distributed Laplace
  Perturbation Algorithm (DLPA).

.. _top:

Distributed Laplace Perturbation Algorithm
==========================================
.. raw:: html

   <div class="addthis_inline_share_toolbox"></div>

Summary
--------
Client and server applications providing Distributed Laplace Perturbation
Algorithm (DLPA).

The DLPA has been introduced by `Vibhor
Rastogi <https://www.linkedin.com/in/vibhor-rastogi-6b680152>`__ and
`Suman Nath <https://www.microsoft.com/en-us/research/people/sumann/>`__ in
"`Differentially Private Aggregation of Distributed Time-Series with
Transformation and
Encryption <http://dl.acm.org/citation.cfm?id=1807247>`__," published in
`SIGMOD 2010 <http://www.sigmod2010.org/index.shtml>`__.


Client
------
This package has client class :class:`dlpa.DLPAClient <dlpa.client.DLPAClient>`.
To create an instance, the constructor takes two arguments:

-  host: Address of a DLPA server,
-  port: Port number of the DLPA server.

Although the client class implements several protocols defined in DLPA,
:meth:`get_key <dlpa.client.DLPAClient.get_key>` and
:meth:`encrypt_noisy_sum <dlpa.client.DLPAClient.encrypt_noisy_sum>`
are the only method users might have interest.

The :meth:`get_key <dlpa.client.DLPAClient.get_key>` requests a client key to
the server.
It takes one argument, client ID, and returns a client key object.

The other method
:meth:`encrypt_noisy_sum <dlpa.client.DLPAClient.encrypt_noisy_sum>` runs the
Entryp-Noisy-Sum protocol, which is the key protocol of DLPA.
It takes the following four arguments:

-  ck: Client key.
-  client\_id: Client ID.
-  value: Scalar or vector to be sent to the server by Encrypt-Sum
   protocol.
-  epsilon: Parameter to generate Laplace noises.

and returns a time slot when the request is attached.

Server
------
``dlpa-server`` command runs a server application of DLPA. The following
is the usage of this command:

::

    usage: dlpa-server [-h] --port PORT --clients NCLIENT
                       [--max-workers MAX_WORKERS] [--key-length M_LENGTH]
                       [--time-span SPAN]

    optional arguments:
      -h, --help            show this help message and exit
      --port PORT           Listening port number.
      --clients NCLIENT     The number of clients.
      --max-workers MAX_WORKERS
                            The maximum number of workers (default: 10).
      --key-length M_LENGTH
                            Bit length of the secret key (default: 2048).
      --time-span SPAN      Second of one time slot.

Note that the port number and the number of clients are necessary
arguments.

You can also starts a server from another python script by using
:meth:`dlpa.server <dlpa.server.server>` function.
The function takes the following keyword arguments:

-  port: Port number the created server listen.
-  max\_workers: The maximum number of workers.
-  nclient: The number of clients connecting this server.
-  m\_length: Bit length of the secret key.

and returns a server object, which has a method ``stop(t)`` to stop the
server within the given time ``t``. Callers are responsible for calling
the method to close the server.

Installation
------------

::

    $ pip install --upgrade psi-dlpa

Additionaly, if you install
`gmpy2 <https://pypi.python.org/pypi/gmpy2>`__, computation time will be
reduced. To install gmpy2 in mac, you also need to install mpc, mpfr,
and libmp. Those three packages are available in
`Homebrew <https://brew.sh/>`__.

API Reference
---------------
.. toctree::
  :glob:
  :maxdepth: 2

  modules/*

License
-------

This software is released under The GNU General Public License Version
3, see `COPYING <COPYING>`__ for more detail.

The functions,
:meth:`powmod() <dlpa.util.powmod>`,
:meth:`invert() <dlpa.util.invert>`,
and :meth:`getprimeover() <dlpa.util.getprimeover>`,
defined in ``src/dlpa/util.py`` are made by Data61 \| CSIRO and released under
the GPLv3. The original source code is
`here <https://github.com/n1analytics/python-paillier/blob/master/phe/util.py>`__.
