#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('requirements.txt') as reqs_file:
    install_requirements = reqs_file.readlines()

with open('requirements_dev.txt') as devreqs_file:
    test_requirements = devreqs_file.readlines()
    test_requirements.extend(install_requirements)

setup(
    name='keymaster_client',
    version='1.0.2',
    author='Adam Pickering',
    author_email='adamkpickering@gmail.com',
    description="Configures wireguard using information received from keymaster-server",
    license="BSD-3-Clause",
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/telus/keymaster-client',
    entry_points={
        'console_scripts': [
            'keymaster_client=keymaster_client.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='keymaster_client keymaster_server keymaster client server wireguard wire guard',
    python_requires='>=3.8',
    install_requires=install_requirements,
    packages=find_packages(include=['keymaster_client']),
    test_suite='test',
    tests_require=test_requirements
)
