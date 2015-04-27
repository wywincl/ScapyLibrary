#!/usr/bin/env python

import sys
from os.path import join, dirname

sys.path.append(join(dirname(__file__), 'src'))
from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup

VERSION = 'dev'

execfile(join(dirname(__file__), 'src', 'Scapy2Library', 'version.py'))


DESCRIPTION = """
Robot Framework keyword library for packet send and recv.
"""[1:-1]


CLASSIFIERS = """
Development Status :: 5 - Production/Stable
License :: Apache Software License
Operating System :: OS Independent
Programming Language :: Python
Topic :: Software Development :: Testing
"""[1:-1]

setup(name         = 'robotframework-Scapy2Library',
      version      = VERSION,
      description  = 'Robot Framework keyword library for packet send and recv',
      long_description = DESCRIPTION,
      author       = 'John.Wang',
      author_email = 'wywincl@gmail.com',
      url          = 'https://github.com/wywincl',
      license      = 'Apache License 2.0',
      keywords     = 'robotframework packet send and recv',
      platforms    = 'any',
      install_requires=[
        'robotframework >= 2.6.0',
      ],
      classifiers  = CLASSIFIERS.splitlines(),
      py_modules=['ez_setup'],
      package_dir  = {'' : 'src'},
      packages     = ['Scapy2Library', 'Scapy2Library.keywords', 'Scapy2Library.utils'],
      package_data = {}
      )
