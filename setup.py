import setuptools
from distutils.core import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name = 'fortinetapi',
    packages = ['fortinetapi'],
    version = '0.1',  # Ideally should be same as your GitHub release tag varsion
    description = 'description',
    author = 'Todd Albiston',
    author_email = 'foxtrot711@gmail.com',
    url = 'https://github.com/talbiston/fortinetapi',
    download_url = 'https://github.com/talbiston/fortinetapi/archive/refs/tags/0.1.tar.gz',
    keywords = ['fortinet', 'Fortimanager', 'fortianalizer'],
    classifiers = [],
)