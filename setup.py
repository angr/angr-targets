import sys
import os
try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]
if sys.platform in ('win32', 'cygwin', 'darwin'):
    setup(name='angr_targets',
          version='0.1',
          packages=packages
         )
else:
    setup(name='angr_targets',
          version='0.1',
          packages=packages,
	      install_requires=['avatar2@https://github.com/avatartwo/avatar2/tarball/master#egg=avatar2-1.1.1']
          )
