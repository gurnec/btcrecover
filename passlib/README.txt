.. -*- restructuredtext -*-

==========================
The Passlib Python Library
==========================

Welcome
=======
Passlib is a password hashing library for Python 2 & 3, which provides
cross-platform implementations of over 30 password hashing algorithms, as well
as a framework for managing existing password hashes. It's designed to be useful
for a wide range of tasks, from verifying a hash found in /etc/shadow, to
providing full-strength password hashing for multi-user application.

The latest documentation can be found online at `<http://packages.python.org/passlib>`_.

Requirements
============
* Python 2.5 - 2.7 or Python 3.x
* py-bcrypt or bcryptor (optional; required only if bcrypt support is needed)
* M2Crypto (optional; accelerates PBKDF2-based hashes)

Installation
============
To install from source using ``setup.py``::

   python setup.py install

For more detailed installation & testing instructions, see "docs/install.rst"

Online Resources
================
* Homepage -   http://passlib.googlecode.com
* Docs -       http://packages.python.org/passlib
* Discussion - http://groups.google.com/group/passlib-users

* PyPI -       http://pypi.python.org/pypi/passlib
* Downloads -  http://code.google.com/p/passlib/downloads
* Source -     http://code.google.com/p/passlib/source
