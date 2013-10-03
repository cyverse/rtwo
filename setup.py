import os
import setuptools
from rtwo.version import get_version

readme = open('README.md').read()

long_description = """
rtwo %s
A unified interface into multiple cloud providers.

To install use pip install git+git://git@github.com:iPlantCollaborativeOpenSource/rtwo.git

----

%s

----

For more information, please see: https://github.com/iPlantCollaborativeOpenSource/rtwo
""" % (get_version('short'), readme)

setuptools.setup(
    name='rtwo',
    version=get_version('short'),
    author='jmatt',
    author_email='jmatt@jmatt.org',
    description="A unified interface into multiple cloud providers.",
    long_description=long_description,
    license="Apache License, Version 2.0",
    url="https://github.com/iPlantCollaborativeOpenSource/rtwo",
    packages=setuptools.find_packages(),
    dependency_links=[
        "git+git://github.com/apache/libcloud.git#egg=apache-libcloud-0.14.0-dev",
        "git+git://github.com/openstack/python-glanceclient.git#egg=python-glanceclient",
        "git+git://github.com/openstack/python-keystoneclient.git#egg=python-keystoneclient",
        "git+git://github.com/openstack/python-novaclient.git#egg=python-novaclient",
        "git+git://github.com/openstack/python-neutronclient.git#egg=python-neutronclient",
        "git+git://github.com/iPlantCollaborativeOpenSource/pycommands.git#egg=pycommands-0.1",
        "git+git://github.com/iPlantCollaborativeOpenSource/rfive.git#egg=rfive-0.1.4",
        "git+git://github.com/jmatt/threepio.git#egg=threepio-0.1.2"
    ],
    install_requires=[
        "apache-libcloud>=0.14",
        "httplib2==0.8",
        "paramiko==1.11.0",
        "python-glanceclient>=0.10.0",
        "python-keystoneclient>=0.3.2",
        "python-novaclient>=2.14.1",
        "python-neutronclient>=2.2.6",
        "pycommands>=0.1",
        "rfive>=0.1.4",
        "threepio>=0.1.2",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
        "Topic :: System",
        "Topic :: System :: Clustering",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Systems Administration"
    ])
