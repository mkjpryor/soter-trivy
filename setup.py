#!/usr/bin/env python3

import os, re
from setuptools import setup, find_namespace_packages


here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


if __name__ == "__main__":
    setup(
        name = 'soter-trivy',
        setup_requires = ['setuptools_scm'],
        use_scm_version = True,
        description = 'Soter scanner implementation for Trivy.',
        long_description = README,
        classifiers = [
            "Programming Language :: Python",
        ],
        author = 'Matt Pryor',
        author_email = 'matt.pryor@stfc.ac.uk',
        url = 'https://github.com/mkjpryor/soter-trivy',
        keywords = 'container image scan security vulnerability configuration issue trivy',
        packages = find_namespace_packages(include = ['soter.*']),
        include_package_data = True,
        zip_safe = False,
        install_requires = [
            'quart',
            'jsonrpc-asyncio-server',
            'soter-scanner-model',
        ],
        entry_points = {
            'console_scripts': [
                # Script to check if the database has ever been installed
                'trivy-db-exists = soter.trivy.db:exists',
                # Script to allow a one-off update of the Trivy vulnerability database
                'trivy-db-update = soter.trivy.db:update',
                # Script to allow periodic updates of the Trivy vulnerability database
                'trivy-db-periodic-update = soter.trivy.db:periodic_update',
            ],
        }
    )
