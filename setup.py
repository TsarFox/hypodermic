#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from hypodermic import __version__


def long_description():
    with open("README.md") as description:
        return description.read()


setup(
    name="Hypodermic",
    license="GPLv3+",
    version=__version__,
    author="Jakob Kreuze",
    author_email="jakob@memeware.net",
    maintainer="Jakob Kreuze",
    maintainer_email="jakob@memeware.net",
    url="https://github.com/TsarFox/hypodermic",
    description="A proof-of-concept shared object injector, designed to be versatile enough for use on any Linux binary.",
    long_description=long_description(),
    download_url="https://github.com/TsarFox/hypodermic",
    packages=["hypodermic"],
    include_package_data=True,
    install_requires=[],
    extras_require={},
    tests_require=[],
    entry_points={"console_scripts": ["hypodermic = hypodermic.main:main"]},
    keywords="systems debug",
    classifiers=[
        "Development Status :: 1 - Planning",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
    ]
)
