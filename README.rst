==================================
  gemato -- Gentoo Manifest Tool
==================================
:Author: Michał Górny
:License: 2-clause BSD license


Introduction
============
gemato provides a reference implementation of the full-tree Manifest
checks as specified in GLEP 74 [#GLEP74]_. Originally focused
on verifying the integrity and authenticity of the Gentoo ebuild
repository, the tool can be used as a generic checksumming tool
for directory trees.


Usage
=====

Verification
------------
The basic purpose of gemato is to verify a directory tree against
Manifest files. In order to do that, run the ``gemato verify`` tool
against the requested directory::

    gemato verify /var/db/repos/gentoo

The tool will automatically locate the top-level Manifest (if any)
and check the specified directory recursively. If a subdirectory
of the Manifest tree is specified, only the specified leaf is checked.


Creating new Manifest tree
--------------------------
Creating a new Manifest tree can be accomplished using the ``gemato
create`` command against the top directory of the new Manifest tree::

    gemato create -p ebuild /var/db/repos/gentoo

Note that for the ``create`` command you always need to specify either
a profile (via ``-p``) or at least a hash set (via ``-H``).

To create OpenPGP signed Manifests::

    gemato create --sign --openpgp-id <YOUR_HSM_ID> \
      --hashes "SHA256 SHA512" \
      --timestamp \
      /path/to/full/tree

This will create a new Manifest file in /path/to/full/tree with a
clearsign OpenPGP signature.

Note that files that start with a dot are not included in the Manifest
and are therefore neigher signed nor verified.


Updating existing Manifests
---------------------------
The ``gemato update`` command is provided to update an existing Manifest
tree::

    gemato update -p ebuild /var/db/repos/gentoo

Alike ``create``, ``update`` also requires specifying a profile (``-p``)
or a hash set (``-H``). The command locates the appropriate top-level
Manifest and updates the specified directory recursively.
If a subdirectory of the Manifest tree is specified, the entries
for the specified leaf and respective Manifest files are updated.


Utility commands
----------------
gemato provides a few other utility commands that provide access to
its crypto backend. These are:

``gemato hash -H <hashes> [<path>...]``
  Print hashes of the specified files in Manifest-like format.

``gemato openpgp-verify [-K <key>] [<path>...]``
  Check OpenPGP cleartext signatures embedded in the specified files.

``gemato openpgp-verify-detached [-K <key>] <sig-file> <data-file>``
  Verify the specified data file against a detached OpenPGP signature.


Requirements
============
gemato is written in Python and compatible with implementations
of Python 3.9+. gemato is currently tested against CPython 3.9
through 3.11 and PyPy3.  gemato core depends only on standard Python
library modules.

Additionally, OpenPGP requires system install of GnuPG 2.2+
and requests_ Python module.  Tests require pytest_, and responses_
for mocking.

API
===

Gemato may be used in python projects that want to verify a downloaded
directory tree::

    $ pip install gemato
 
example script::

    import gemato
    from gemato.exceptions import GematoException

    import logging
    import os
    
    try:
        gemato_manifest = gemato.recursiveloader.ManifestRecursiveLoader(
                            os.path.join(os.getcwd(), 'Manifest'),
                            verify_openpgp=True,
                            openpgp_env=gemato.openpgp.OpenPGPSystemEnvironment())
        gemato_manifest.assert_directory_verifies()
    except GematoException as e:
        logging.error(e)

See portage/lib/portage/sync/modules/rsync/rsync.py for a more complete example.


References and footnotes
========================
.. [#GLEP74] GLEP 74: Full-tree verification using Manifest files
   (https://www.gentoo.org/glep/glep-0074.html)

.. _requests: https://2.python-requests.org/en/master/
.. _pytest: https://docs.pytest.org/en/stable/
.. _responses: https://github.com/getsentry/responses
