#!/usr/bin/env python
from distutils.core import setup

try:
    try:
        setup(name='V3n0M',
              version='426',
              description="Popular SQLi and Pentesting scanner in Python 3",
              author='Da-vinci',
              author_email='not available',
              url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
              package_dir={'v3n0m': 'src'},
              packages=['v3n0m'])
    except Exception as msg:
        # gotta reverse this shit code first
        print(msg)
        from setuptools import setup

        setup(name='V3n0M',
              version='426',
              description="Popular SQLi and Pentesting scanner in Python 3",
              author='Da-vinci',
              author_email='not available',
              url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
              package_dir={'v3n0m': 'src'},
              packages=['v3n0m'])
except Exception as verb:
    print(verb)
