# Distributed Laplace Perturbation Algorithm
[![GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://www.gnu.org/copyleft/gpl.html)
[![Build Status](https://travis-ci.org/jkawamoto/psi-dlpa.svg?branch=master)](https://travis-ci.org/jkawamoto/psi-dlpa)
[![wercker status](https://app.wercker.com/status/e2799a5e4bf381734ac6d2d5dc844f3e/s/master "wercker status")](https://app.wercker.com/project/byKey/e2799a5e4bf381734ac6d2d5dc844f3e)
[![Release](https://img.shields.io/badge/release-0.3.0-brightgreen.svg)](https://github.com/jkawamoto/psi-dlpa/releases/tag/0.3.0)

Client and server applications providing Distributed Laplace Perturbation
Algorithm (DLPA).

The DLPA has been introduced by
[Vibhor Rastogi](https://www.linkedin.com/in/vibhor-rastogi-6b680152)
and [Suman Nath](https://www.microsoft.com/en-us/research/people/sumann/)
in "[Differentially Private Aggregation of Distributed Time-Series with
Transformation and Encryption](http://dl.acm.org/citation.cfm?id=1807247),"
and published in [SIGMOD 2010](http://www.sigmod2010.org/index.shtml).

## Client
This package has client class `dlpa.DLPAClient`.
To create an instance, the constructor takes two arguments:

* host: Address of a DLPA server,
* port: Port number of the DLPA server.

Although the client class implements several protocols defined in DLPA,
`get_key` and `encrypt_noisy_sum` are the only method users might have interest.

The `get_key` requests a client key to the server.
It takes one argument, client ID, and returns a client key object.

The other method `encrypt_noisy_sum` runs the Entryp-Noisy-Sum protocol,
which is the key protocol of DLPA.
It takes the following four arguments:

* ck: Client key.
* client_id: Client ID.
* value: Scalar or vector to be sent to the server by Encrypt-Sum
  protocol.
* epsilon: Parameter to generate Laplace noises.

and returns a time slot when the request is attached.

## Server
`dlpa-server` command runs a server application of DLPA.
The following is the usage of this command:

```
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
```

Note that the port number and the number of clients are necessary arguments.

You can also starts a server from another python script by using `dlpa.server`
function.
The function takes the following keyword arguments:

* port: Port number the created server listen.
* max_workers: The maximum number of workers.
* nclient: The number of clients connecting this server.
* m_length: Bit length of the secret key.

and returns a server object, which has a method `stop(t)` to stop the server
within the given time `t`.
Callers are responsible for calling the method to close the server.

## Installation
```
$ pip install --upgrade psi-dlpa
```

Additionaly, if you install [gmpy2](https://pypi.python.org/pypi/gmpy2),
computation time will be reduced.
To install gmpy2 in mac, you also need to install mpc, mpfr, and libmp.
Those three packages are available in [Homebrew](https://brew.sh/).

## License
This software is released under The GNU General Public License Version 3,
see [COPYING](COPYING) for more detail.

The functions, powmod, invert, and getprimeover, defined in `src/dlpa/util.py`
are made by Data61 | CSIRO and released under the GPLv3.
The original source code is
[here](https://github.com/n1analytics/python-paillier/blob/master/phe/util.py).
