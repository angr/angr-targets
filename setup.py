import sys
try:
    from setuptools import setup
    from setuptools import find_packages
except ImportError:
    from distutils.core import setup

if sys.platform in ('win32', 'cygwin', 'darwin'):
    setup(name='angr_targets',
          version='0.1',
          packages=['angr_targets'],
         )
else:
    setup(name='angr_targets',
          version='0.1',
          packages=['angr_targets'],
          install_requires=['avatar2']
          )
