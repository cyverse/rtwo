import os
import sys
import doctest

from distutils.core import Command
from unittest import TextTestRunner, TestLoader
from glob import glob
from os.path import splitext, basename, join as pjoin
import setuptools
from rtwo.version import get_version, read_requirements

readme = open('README.md').read()
dependencies, requirements = read_requirements('requirements.txt')

long_description = """
rtwo %s
A unified interface into multiple cloud providers.

To install use pip install git+git://git@github.com:iPlantCollaborativeOpenSource/rtwo.git

----

%s

----

For more information, please see: https://github.com/iPlantCollaborativeOpenSource/rtwo
""" % (get_version('short'), readme)


TEST_PATHS = ['rtwo/test',]
class TestCommand(Command):
    description = "run test suite"
    user_options = []

    def initialize_options(self):
        THIS_DIR = os.path.abspath(os.path.split(__file__)[0])
        sys.path.insert(0, THIS_DIR)
        for test_path in TEST_PATHS:
            sys.path.insert(0, pjoin(THIS_DIR, test_path))
        self._dir = os.getcwd()

    def finalize_options(self):
        pass

    def run(self):
        try:
            import mock
            mock
        except ImportError:
            print('Missing "mock" library. mock is library is needed '
                  'to run the tests. You can install it using pip: '
                  'pip install mock')
            sys.exit(1)


        status = self._run_tests()
        sys.exit(status)

    def _run_tests(self):
        secrets_current = pjoin(self._dir, 'rtwo/test', 'secrets.py')
        secrets_dist = pjoin(self._dir, 'rtwo/test', 'secrets.py.dist')

        if not os.path.isfile(secrets_current):
            print("Missing " + secrets_current)
            print("Maybe you forgot to copy it from .dist:")
            print("cp rtwo/test/secrets.py.dist rtwo/test/secrets.py")
            sys.exit(1)

        mtime_current = os.path.getmtime(secrets_current)
        mtime_dist = os.path.getmtime(secrets_dist)

        if mtime_dist > mtime_current:
            print("It looks like test/secrets.py file is out of date.")
            print("Please copy the new secrets.py.dist file over otherwise" +
                  " tests might fail")

        testfiles = []
        for test_path in TEST_PATHS:
            for t in glob(pjoin(self._dir, test_path, 'test_*.py')):
                testfiles.append('.'.join(
                    [test_path.replace('/', '.'), splitext(basename(t))[0]]))
        tests = TestLoader().loadTestsFromNames(testfiles)

        t = TextTestRunner(verbosity=2)
        res = t.run(tests)
        return not res.wasSuccessful()

setuptools.setup(
    name='rtwo',
    version=get_version('short'),
    author='iPlant Collaborative',
    author_email='atmodevs@gmail.com',
    description="A unified interface into multiple cloud providers.",
    long_description=long_description,
    license="BSD License, 3 clause",
    url="https://github.com/iPlantCollaborativeOpenSource/rtwo",
    packages=setuptools.find_packages(),
    dependency_links=dependencies,
    install_requires=requirements,
    cmdclass={
        'test': TestCommand,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
        "Topic :: System",
        "Topic :: System :: Clustering",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Systems Administration"
    ])
