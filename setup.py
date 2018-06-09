try:
    from setuptools import setup
    from setuptools import find_packages
except ImportError:
    from distutils.core import setup

setup(name='angr_targets',
      version='0.1',
      packages=['angr_targets'],
      )
