#!/usr/bin/env python

import setuptools

setuptools.setup(
        name='stardust.pyspark',
        version='0.1',
        description='Helper routines for processing STARDUST data using pyspark.',
        url='https://github.com/CAIDA/stardust-tools',
        author='Shane Alcock',
        author_email='shane@alcock.co.nz',
        packages=setuptools.find_packages(),
        install_requires=[
            'pyspark', 'pyarrow'],
)
