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
    author='Adam Pickering',
    author_email='adamkpickering@gmail.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
    ],
    description="Configures wireguard using information received from keymaster-server",
    entry_points={
        'console_scripts': [
            'keymaster_client=keymaster_client.cli:main',
        ],
    },
    install_requires=install_requirements,
    license="Proprietary",
    long_description=readme,
    include_package_data=True,
    keywords='keymaster_client',
    name='keymaster_client',
    packages=find_packages(include=['keymaster_client']),
    package_data={},
    test_suite='test',
    tests_require=test_requirements,
    url='https://github.com/telus/keymaster-client',
    version='0.0.6',
    zip_safe=False,
)
