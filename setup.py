import shutil
from setuptools import setup

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    content = f.readlines()
    requirements = [x.strip() for x in content]

shutil.copyfile('enum4linux-ng.py', 'enum4linux-ng')

setup(
    name='enum4linux-ng',
    version='1.1.0',
    author='mw',
    description='A next generation version of enum4linux',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/cddmp/enum4linux-ng',
    classifiers=[
        'Environment :: Console'
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    scripts=['enum4linux-ng']
)
