#
# __init__.py
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
"""Client and Server of the distributed Laplace Perturbation Algorithm service.

By default, this package exports two classes:

* :class:`DLPAClient <dlpa.client.DLPAClient>`, a client of DLPA service;
* :class:`DLPAServicer <dlpa.server.DLPAServicer>`, a servicer of DLPA service.

and one function:

* :meth:`server <dlpa.server.server>` which starts a DLPA server.

The distributed Laplace Perturbation Algorithm (DLPA) service is defined in
``dlpa.proto``, see this file for more information.
"""
# pylint: disable=import-error
from dlpa.client import DLPAClient
from dlpa.server import DLPAServicer
from dlpa.server import server
