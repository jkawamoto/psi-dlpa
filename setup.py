#
# setup.py
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
"""Package information about DLPA.
"""
from os import path
from setuptools import setup, find_packages


def read(fname):
    """Read a file.
    """
    return open(path.join(path.dirname(__file__), fname)).read()


def load_requires_from_file(filepath):
    """Read a package list from a given file path.
    Args:
      filepath: file path of the package list.
    Returns:
      a list of package names.
    """
    with open(filepath) as fp:
        return [pkg_name.strip() for pkg_name in fp.readlines()]


setup(
    name="psi-dlpa",
    use_scm_version=True,
    author="Junpei Kawamoto",
    author_email="kawamoto.junpei@gmail.com",
    description="Client/Server for Distributed Laplace Perturbation Algorithm",
    long_description=read("README.rst"),
    url="https://github.com/jkawamoto/psi-dlpa",
    packages=find_packages(exclude=["tests"]),
    setup_requires=[
        "setuptools_scm"
    ],
    install_requires=load_requires_from_file("requirements.txt"),
    extras_require={
        "gmpy2": ["gmpy2>=2.0.8"]
    },
    entry_points={
        "console_scripts": [
            "dlpa-server = dlpa.server:main",
        ]
    },
    test_suite="tests.suite",
    license="GPLv3",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
        "Topic :: Scientific/Engineering :: Information Analysis"
    ]
)
