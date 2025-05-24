#!/usr/bin/env python3
"""
Setup script for IP WHOIS lookup tool.
"""

import re
import os
from setuptools import setup, find_packages

# Read version from package __init__.py
with open(os.path.join('whois_tool', '__init__.py'), 'r') as f:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        version = '0.1.0'

# Read long description from README.md
with open('README.md', 'r') as f:
    long_description = f.read()

# Read requirements from requirements.txt
with open('requirements.txt', 'r') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='ip-whois-tool',
    version=version,
    description='A tool for looking up WHOIS information for IP addresses',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='IP WHOIS Tool Contributors',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/ip_whois_tool',
    packages=find_packages(include=['whois_tool', 'whois_tool.*']),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ip-whois=whois_tool.cli:main',
            'ip-lookup=whois_tool.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Internet',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    python_requires='>=3.8',
    keywords='whois, ip, networking, rdap, dns',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/ip_whois_tool/issues',
        'Source': 'https://github.com/yourusername/ip_whois_tool',
    },
    # Use include_package_data with MANIFEST.in instead of explicit package_data
    package_data={
        'whois_tool': [
            '../example_ips.txt',
            '../README.md',
            '../LICENSE',
            '../CHANGELOG.md',
        ],
    },
    # Create required directories
    data_files=[
        ('share/ip_whois_tool/data/cache', []),
        ('share/ip_whois_tool/data/logs', []),
    ],
)

