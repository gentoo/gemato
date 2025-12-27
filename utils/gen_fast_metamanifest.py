#!/usr/bin/env python
# Ultra-optimized Meta-Manifest writing.
# (c) 2017-2023 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

import datetime
import glob
import multiprocessing
import os
import os.path
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))

import gen_fast_manifest


def manifest_dir_generator(iter_n):
    with open('profiles/categories') as f:
        categories = [x.strip() for x in f]

    for c in categories:
        if iter_n == 1:
            # all package directories
            for d in glob.glob(os.path.join(c, '*/')):
                yield d
            # md5-cache for the category
            d = os.path.join('metadata/md5-cache', c)
            if os.path.exists(d):
                yield d
        elif iter_n == 2:
            # category directory
            if os.path.exists(c):
                yield c

    if iter_n == 1:
        # few special metadata subdirectories
        yield 'metadata/dtd'
        yield 'metadata/glsa'
        yield 'metadata/news'
        yield 'metadata/xml-schema'

        # independent top-level dirs
        yield 'eclass'
        yield 'licenses'
        yield 'profiles'
    elif iter_n == 2:
        # md5-cache depends on cache dirs from iter 1
        yield 'metadata/md5-cache'
    elif iter_n == 3:
        # remaining top-level dir
        yield 'metadata'
    elif iter_n == 4:
        # finally, the top-level Manifest
        yield '.'


def make_toplevel(d, ts, pgp_key):
    for suffix in ('.gz', ''):
        src = os.path.join(d, 'Manifest' + suffix)
        if os.path.exists(src):
            dstsplit = os.path.join(d, 'Manifest.files' + suffix)
            dsttop = os.path.join(d, 'Manifest')
            os.rename(src, dstsplit)

            me = gen_fast_manifest.get_manifest_entry('MANIFEST',
                    dstsplit, 'Manifest.files' + suffix)
            data = me + b'\n' + ts

            if pgp_key is not None:
                gpg = os.environ.get('GNUPG', 'gpg')
                p = subprocess.Popen([gpg, '--batch', '-u', pgp_key,
                                      '--armor', '--clearsign'],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                sout, serr = p.communicate(data)
                if p.wait() != 0:
                    raise ValueError(f'GPG error: {serr}')
                data = sout

            with open(dsttop, 'wb') as f:
                f.write(data)

            break


def gen_metamanifest(top_dir, pgp_key):
    os.chdir(top_dir)

    # pre-populate IGNORE entries
    with open('metadata/Manifest', 'wb') as f:
        f.write(b'''IGNORE timestamp
IGNORE timestamp.chk
IGNORE timestamp.commit
IGNORE timestamp.x
''')
    for mdir in ('dtd', 'glsa', 'news', 'xml-schema'):
        with open(os.path.join('metadata', mdir, 'Manifest'), 'wb') as f:
            f.write(b'''IGNORE timestamp.chk
IGNORE timestamp.commit
''')
    with open('Manifest', 'wb') as f:
        f.write(b'''IGNORE distfiles
IGNORE local
IGNORE lost+found
IGNORE packages
''')

    p = multiprocessing.Pool()

    # generate 1st batch of sub-Manifests
    # expecting 20000+ items, so use iterator with a reasonably large
    # chunksize
    p.map(gen_fast_manifest.gen_manifest, manifest_dir_generator(1), chunksize=64)

    # special directories: we split Manifest there, and add timestamp
    ts = datetime.datetime.now(datetime.timezone.utc).strftime(
            'TIMESTAMP %Y-%m-%dT%H:%M:%SZ\n').encode('ascii')
    make_toplevel('metadata/glsa', ts, pgp_key)
    make_toplevel('metadata/news', ts, pgp_key)

    # remaining batches
    # the lists are short, so let's pass them and let map() choose optimal
    # chunksize
    p.map(gen_fast_manifest.gen_manifest, list(manifest_dir_generator(2)))
    p.map(gen_fast_manifest.gen_manifest, list(manifest_dir_generator(3)))
    p.map(gen_fast_manifest.gen_manifest, list(manifest_dir_generator(4)))

    # final split
    ts = datetime.datetime.now(datetime.timezone.utc).strftime(
            'TIMESTAMP %Y-%m-%dT%H:%M:%SZ\n').encode('ascii')
    make_toplevel('', ts, pgp_key)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        print(f'Usage: {sys.argv[0]} <top-directory> [<openpgp-key>]')
        sys.exit(1)

    gen_metamanifest(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
