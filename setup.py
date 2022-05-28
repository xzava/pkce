#!/usr/bin/env python3

import os
from setuptools import setup

directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(directory, 'README.md'), encoding='utf-8') as f:
  long_description = f.read()

setup(name='pkce',
      version='0.0.1',
      description='Python PKCE token exchange for OAuth code flow',
      author='Mike Hall - Kaurifund.com',
      license='MIT',
      long_description=long_description,
      long_description_content_type='text/markdown',
      packages = ['pkce'],
      classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License"
      ],
      # install_requires=['python-jose'],
      python_requires='>=3.8',
      extras_require={
        'testing': ["pytest"],
        'crypto': ["python-jose[cryptography]"],
      },
      include_package_data=True)