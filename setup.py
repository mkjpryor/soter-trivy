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
        description = 'HTTP API over Trivy CLI.',
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
        ],
    )
