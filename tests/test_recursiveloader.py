# gemato: Recursive loader tests
# (c) 2017-2022 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import contextlib
import datetime
import gzip
import itertools
import os
import re

import pytest

import gemato.cli
from gemato.compression import open_potentially_compressed_path
from gemato.exceptions import (
    ManifestMismatch,
    ManifestInvalidPath,
    ManifestIncompatibleEntry,
    ManifestCrossDevice,
    ManifestSymlinkLoop,
    ManifestNoSupportedHashes,
    ManifestInsecureHashes,
    )
from gemato.hash import hash_path
from gemato.manifest import ManifestPathEntry, ManifestFileEntry
from gemato.recursiveloader import ManifestRecursiveLoader

from tests.test_compression import COMPRESSION_ALGOS
from tests.testutil import disallow_writes


@pytest.fixture(scope='module')
def layout_cache():
    cache = {}
    yield cache
    for layout, tmp_path in cache.items():
        layout.cleanup(tmp_path)


class LayoutFactory:
    """Factory to install layouts in temporary directory with cleanup"""

    def __init__(self, tmp_path_factory, name, layout_cache):
        self.tmp_path_factory = tmp_path_factory
        self.name = name
        self.layout_cache = layout_cache
        self.layouts = []

    def create(self, layout, readonly=False):
        if readonly:
            if layout not in self.layout_cache:
                tmp_path = self.tmp_path_factory.mktemp(layout.__name__)
                layout.create(tmp_path)
                disallow_writes(tmp_path)
                self.layout_cache[layout] = tmp_path
            return self.layout_cache[layout]

        tmp_path = self.tmp_path_factory.mktemp(self.name)
        layout.create(tmp_path)
        self.layouts.append((layout, tmp_path))
        return tmp_path

    def cleanup(self):
        for layout, tmp_path in self.layouts:
            layout.cleanup(tmp_path)


@pytest.fixture
def layout_factory(request, tmp_path_factory, layout_cache):
    # stolen from pytest
    name = request.node.name
    name = re.sub(r"[\W]", "_", name)
    MAXVAL = 30
    name = name[:MAXVAL]

    factory = LayoutFactory(tmp_path_factory, name, layout_cache)
    yield factory
    factory.cleanup()


class BaseLayout:
    TOP_MANIFEST = 'Manifest'
    DIRS = []
    MANIFESTS = {}
    FILES = {}

    @classmethod
    def create(cls, tmp_path):
        """Create layout's files in the specified directory"""
        cls.FILES = dict(cls.FILES)
        cls.FILES.update(cls.MANIFESTS)
        for d in cls.DIRS:
            os.mkdir(tmp_path / d)
        for f, contents in cls.FILES.items():
            bincontents = contents.encode('utf8')
            if f.endswith('.gz'):
                fclass = gzip.GzipFile
            else:
                fclass = open
            with fclass(tmp_path / f, 'wb') as of:
                of.write(bincontents)

    @classmethod
    def cleanup(cls, tmp_path):
        """Perform any necessary pre-cleanup tasks"""
        pass


class BasicTestLayout(BaseLayout):
    """Commonplace Manifest tree layout"""

    DIRS = ['sub', 'sub/deeper', 'other']
    MANIFESTS = {
        'Manifest': '''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 128 MD5 30fd28b98a23031c72793908dd35c530
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': '''
MANIFEST deeper/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/deeper/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'other/Manifest': '',
    }
    FILES = {
        'sub/stray': '',
        'sub/deeper/test': '',
    }

    # rewriting implies stripping leading whitespace
    MANIFESTS_REWRITTEN = {
        'Manifest': '''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 127 MD5 51d05790f4208f3bdf1087ab31b6c228
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'sub/Manifest': '''
MANIFEST deeper/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'sub/deeper/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'other/Manifest': '',
    }
    MANIFESTS_SORTED = {
        'Manifest': '''
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST sub/Manifest 127 MD5 de990fbccb1261da02c7513dfec56045
TIMESTAMP 2017-01-01T01:01:01Z
'''.lstrip(),
        'sub/Manifest': '''
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST deeper/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c
'''.lstrip(),
        'sub/deeper/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'other/Manifest': '',
    }
    MANIFESTS_SHA1 = {
        'Manifest': '''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 195 SHA1 bae1428bfbb4ea08a736975217819be285df4474
MANIFEST other/Manifest 0 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'sub/Manifest': '''
MANIFEST deeper/Manifest 58 SHA1 4b40f4102dd71fb2083ce9a8d8af6d7e49c281c4
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA stray 0 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
'''.lstrip(),
        'sub/deeper/Manifest': '''
DATA test 0 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
'''.lstrip(),
        'other/Manifest': '',
    }


class SubTimestampLayout(BaseLayout):
    """Layout that places TIMESTAMP in a sub-Manifest"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'sub/Manifest': '''
TIMESTAMP 2017-01-01T01:01:01Z
''',
    }


class MultiManifestLayout(BaseLayout):
    """Layout with multiple Manifest files in a subdirectory"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest.a 50 MD5 33fd9df6d410a93ff859d75e088bde7e
MANIFEST sub/Manifest.b 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'sub/Manifest.a': '''
DATA foo 32 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest.b': '''
TIMESTAMP 2017-01-01T01:01:01Z
''',
    }
    FILES = {
        'sub/foo': '1234567890123456',
    }


class MultiTopManifestLayout(BaseLayout):
    """Layout with multiple Manifest files in the top directory"""

    DIRS = ['sub']
    FILES = {
        'Manifest': '''
MANIFEST Manifest.a 62 MD5 ae43485cc7bd080800a64b09bbfa53a8
MANIFEST Manifest.b 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'Manifest.a': '''
MANIFEST sub/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'Manifest.b': '''
TIMESTAMP 2017-01-01T01:01:01Z
''',
        'sub/Manifest': '',
    }


class DuplicateEntryLayout(BaseLayout):
    """Layout with duplicate (matching) entry for a file"""

    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'test': '',
    }


class DuplicateManifestEntryLayout(BaseLayout):
    """Layout with duplicate (matching) entry for a Manifest"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
MANIFEST sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
''',
        'sub/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'sub/test': '',
    }


class DuplicateManifestAsDataEntryLayout(BaseLayout):
    """Layout with duplicate DATA entry for a Manifest"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DATA sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
''',
        'sub/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'sub/test': '',
    }


class DuplicateEntryInSubManifestLayout(BaseLayout):
    """Layout with duplicate entry in sub-Manifest"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'sub/test': '',
    }


class DuplicateEbuildEntryLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
EBUILD test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    FILES = {
        'test.ebuild': '',
    }


class PotentialAuxEntryLayout(BaseLayout):
    DIRS = ['files']
    MANIFESTS = {
        'Manifest': '',
    }
    FILES = {
        'files/test.patch': '',
    }


class DuplicateAuxEntryLayout(PotentialAuxEntryLayout):
    MANIFESTS = {
        'Manifest': '''
DATA files/test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }


class DisjointHashSetEntryLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 9e107d9d372bb6826bd81d3542a419d6
DATA test 0 SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
''',
    }
    FILES = {
        'test': '',
    }


class IncompatibleTypeLayout(BaseLayout):
    """A layout with two incompatible entries for the same file"""

    MANIFESTS = {
        'Manifest': '''
DATA metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }


class MismatchedSizeLayout(BaseLayout):
    """A layout with two entries with different size for the same file"""

    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test 32 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }


class MismatchedChecksumLayout(BaseLayout):
    """A layout with two entries with different hash for the same file"""

    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test 0 MD5 9e107d9d372bb6826bd81d3542a419d6
''',
    }


class IgnoreEntryLayout(BaseLayout):
    DIRS = ['bar']
    MANIFESTS = {
        'Manifest': '''
IGNORE foo
IGNORE bar
''',
    }
    FILES = {
        'foo': 'test',
        'bar/baz': 'test',
    }


class MiscEntryLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }


class CrossDeviceLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
DATA sub/version 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    @classmethod
    def create(cls, tmp_path):
        st1 = os.stat(tmp_path)
        try:
            st2 = os.stat('/proc/version')
        except OSError:
            pytest.skip('Unable to stat /proc/version')
        if st1.st_dev == st2.st_dev:
            pytest.skip('/proc/version is not on a distinct filesystem')
        super().create(tmp_path)
        os.symlink('/proc', tmp_path / 'sub')


class CrossDeviceEmptyLayout(CrossDeviceLayout):
    MANIFESTS = {
        'Manifest': '',
    }


class CrossDeviceIgnoreLayout(CrossDeviceLayout):
    MANIFESTS = {
        'Manifest': '''
IGNORE sub
''',
    }


class DotFileLayout(BaseLayout):
    """Layout for testing ignoring dotfiles"""

    DIRS = ['.bar']
    MANIFESTS = {
        'Manifest': '',
    }
    FILES = {
        '.foo': '',
        '.bar/baz': '',
    }


class DirForFileLayout(BaseLayout):
    """A layout where directory replaced a file"""

    DIRS = ['test']
    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''
    }


class UnreadableDirLayout(BaseLayout):
    DIRS = ['test']
    MANIFESTS = {
        'Manifest': '',
    }

    @classmethod
    def create(cls, tmp_path):
        super().create(tmp_path)
        os.chmod(tmp_path / 'test', 0)

    @classmethod
    def cleanup(cls, tmp_path):
        # restore permissions to allow cleanup
        os.chmod(tmp_path / 'test', 0o755)


class CompressedTopManifestLayout(BaseLayout):
    TOP_MANIFEST = 'Manifest.gz'
    MANIFESTS = {
        'Manifest.gz': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'test': '',
    }


class CompressedSubManifestLayout(BaseLayout):
    # we can't compress locally here since we need stable result
    SUB_MANIFEST_B64 = b'''
H4sICHX68FkCA01hbmlmZXN0AHNxDHFUKEktLlEwUPB1MVVIMTFMsUhOsbRIMzBIMjIwSbW0
MDCwtLRITU6zMDEyT+UCAJqyznMxAAAA
'''
    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
MANIFEST sub/Manifest.gz 78 MD5 9c158f87b2445279d7c8aac439612fba
''',
        'sub/Manifest.gz': '',
    }
    FILES = {
        'sub/test': '',
    }

    @classmethod
    def create(cls, tmp_path):
        super().create(tmp_path)
        with open(tmp_path / 'sub/Manifest.gz', 'wb') as f:
            f.write(base64.b64decode(cls.SUB_MANIFEST_B64))


class CompressedManifestSortLayout(BaseLayout):
    """Layout to test ordering of mixed compressed/uncompressed Manifests"""

    TOP_MANIFEST = 'Manifest.gz'
    DIRS = ['a']
    MANIFESTS = {
        'Manifest.gz': '''
MANIFEST a/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/Manifest': '',
        'a/stray': '',
    }


class MultipleStrayFilesLayout(BaseLayout):
    """Regression test for adding multiple stray files"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
    }
    FILES = {
        'sub/file.a': '',
        'sub/file.b': '',
        'sub/file.c': '',
    }


class StrayManifestLayout(BaseLayout):
    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
        'sub/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'sub/test': '',
    }


class StrayCompressedManifestLayout(BaseLayout):
    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
        'sub/Manifest.gz': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'sub/test': '',
    }


class StrayInvalidManifestLayout(BaseLayout):
    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
        # technically it's not a Manifest but we want to verify that
        # it is not clobbered
        'sub/Manifest': '''
I AM SOOO INVALID
''',
    }
    FILES = {
        'sub/test': '',
    }


class StrayInvalidCompressedManifestLayout(BaseLayout):
    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
    }
    FILES = {
        'sub/test': '',
    }

    COMPRESSION_SUFFIX = 'gz'

    @classmethod
    def create(cls, tmp_path):
        super().create(tmp_path)
        with open(tmp_path / f'sub/Manifest.{cls.COMPRESSION_SUFFIX}',
                  'w') as f:
            # important: this is written uncompressed
            f.write('I AM SOOO INVALID\n')


class StrayInvalidCompressedManifestBz2Layout(
        StrayInvalidCompressedManifestLayout):
    COMPRESSION_SUFFIX = 'bz2'


class StrayInvalidCompressedManifestLzmaLayout(
        StrayInvalidCompressedManifestLayout):
    COMPRESSION_SUFFIX = 'lzma'


class StrayInvalidCompressedManifestXzLayout(
        StrayInvalidCompressedManifestLayout):
    COMPRESSION_SUFFIX = 'xz'


class FilenameWhitespaceLayout(BaseLayout):
    FILENAME = '  foo bar  '
    MANIFESTS = {
        'Manifest': '''
DATA \\x20\\x20foo\\x20bar\\x20\\x20 0 \
MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        FILENAME: '',
    }

    MANIFESTS_REWRITTEN = {k: v.lstrip() for k, v in MANIFESTS.items()}


class FilenameBackslashLayout(BaseLayout):
    FILENAME = 'foo\\bar'
    MANIFESTS = {
        'Manifest': '''
DATA foo\\x5Cbar 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        FILENAME: '',
    }

    MANIFESTS_REWRITTEN = {k: v.lstrip() for k, v in MANIFESTS.items()}


class NewManifestLayout(BaseLayout):
    DIRS = ['sub']
    FILES = {
        'test': '',
        'sub/test': '',
    }


class NestedManifestLayout(BaseLayout):
    DIRS = ['a', 'a/x', 'a/y', 'a/z', 'b']
    MANIFESTS = {
        'Manifest': '''
MANIFEST a/Manifest 119 MD5 6956767cfbb3276adbdce86cca559719
MANIFEST b/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/Manifest': '''
MANIFEST x/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST z/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/x/Manifest': '',
        'a/z/Manifest': '',
        'b/Manifest': '',
    }
    FILES = {
        'test': '',
        'a/test': '',
        'a/x/test': '',
        'a/y/test': '',
        'a/z/test': '',
        'b/test': '',
    }


class AddToMultiManifestLayout(BaseLayout):
    DIRS = ['a', 'b']
    MANIFESTS = {
        'Manifest': '''
MANIFEST a/Manifest.a 46 MD5 9694e21e0a3f2e49cbc0fc9ab44797e8
MANIFEST a/Manifest.b 46 MD5 93f00cb02b04ad2520414af7983ebae7
'''.lstrip(),
        'a/Manifest': '''
DATA c 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'a/Manifest.a': '''
DATA a 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
        'a/Manifest.b': '''
DATA b 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip(),
    }
    FILES = {
        'a/a': '',
        'a/b': '',
        'a/c': '',
        'b/test': '',
    }


class SubManifestMismatchLayout(BaseLayout):
    """Sub-Manifest whose checksum is mismatched"""

    DIRS = ['a']
    MANIFESTS = {
        'Manifest': '''
MANIFEST a/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }
    FILES = {
        'a/test': '',
    }


class NonexistingDirectoryLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }


class SymlinkLoopLayout(BaseLayout):
    """A layout with a directory that contains a symlink to itself"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '',
    }

    @classmethod
    def create(cls, tmp_path):
        super().create(tmp_path)
        os.symlink('.', tmp_path / 'sub/sub')


class SymlinkLoopIgnoreLayout(SymlinkLoopLayout):
    """A layout with a directory that contains a symlink to itself"""

    DIRS = ['sub']
    MANIFESTS = {
        'Manifest': '''
IGNORE sub
''',
    }


class MismatchedFileLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
DATA test 11 MD5 5f8db599de986fab7a21625b7916589c
''',
    }
    FILES = {
        'test': 'test string',
    }


class MismatchedFileFutureTimestampLayout(BaseLayout):
    MANIFESTS = {
        'Manifest': '''
TIMESTAMP
DATA test 11 SHA1 561295c9cbf9d6b2f6428414504a8deed3020641
''',
    }
    FILES = {
        'test': 'test string',
    }

    @classmethod
    def create(cls, tmp_path):
        super().create(tmp_path)
        future_dt = (datetime.datetime.now(datetime.timezone.utc) +
                     datetime.timedelta(days=1))
        with open(tmp_path / 'Manifest', 'w') as f:
            f.write(cls.MANIFESTS['Manifest'].replace(
                'TIMESTAMP',
                f'TIMESTAMP {future_dt.strftime("%Y-%m-%dT%H:%M:%SZ")}'))


class UnknownHashLayout(BaseLayout):
    """Layout with a supported and unknown hash"""

    MANIFESTS = {
        'Manifest': '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e X-UNKNOWN 0123456789abcdef
''',
    }
    FILES = {
        'test': '',
    }


class UnknownHashOnlyLayout(BaseLayout):
    """Layout with unknown hash only"""

    MANIFESTS = {
        'Manifest': '''
DATA test 0 X-UNKNOWN 0123456789abcdef
''',
    }
    FILES = {
        'test': '',
    }


class SecureHashLayout(BaseLayout):
    """Layout using at least one cryptographically secure hash"""

    MANIFESTS = {
        "Manifest": """
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
""",
    }
    FILES = {
        "test": "",
    }


FLAT_LAYOUTS = [
    DuplicateEntryLayout,
    DuplicateEbuildEntryLayout,
    DuplicateAuxEntryLayout,
    DisjointHashSetEntryLayout,
    IncompatibleTypeLayout,
    MismatchedSizeLayout,
    MismatchedChecksumLayout,
    IgnoreEntryLayout,
    MiscEntryLayout,
    CrossDeviceLayout,
    CrossDeviceEmptyLayout,
    CrossDeviceIgnoreLayout,
    DotFileLayout,
    DirForFileLayout,
    UnreadableDirLayout,
    MultipleStrayFilesLayout,
    StrayManifestLayout,
    StrayCompressedManifestLayout,
    StrayInvalidManifestLayout,
    StrayInvalidCompressedManifestLayout,
    StrayInvalidCompressedManifestBz2Layout,
    StrayInvalidCompressedManifestLzmaLayout,
    StrayInvalidCompressedManifestXzLayout,
    FilenameWhitespaceLayout,
    FilenameBackslashLayout,
    NonexistingDirectoryLayout,
    SymlinkLoopLayout,
    SymlinkLoopIgnoreLayout,
    MismatchedFileLayout,
    UnknownHashLayout,
    UnknownHashOnlyLayout,
]
SUB_LAYOUTS = [
    SubTimestampLayout,
    DuplicateManifestEntryLayout,
    DuplicateManifestAsDataEntryLayout,
    DuplicateEntryInSubManifestLayout,
]
ALL_LAYOUTS = FLAT_LAYOUTS + SUB_LAYOUTS + [
    BasicTestLayout,
    MultiManifestLayout,
    MultiTopManifestLayout,
    CompressedSubManifestLayout,
    NestedManifestLayout,
    AddToMultiManifestLayout,
    SubManifestMismatchLayout,
]


@pytest.mark.parametrize(
    'layout,path,recursive,expected',
    [(layout, None, False, ['Manifest']) for layout in ALL_LAYOUTS] +
    [(layout, '', True, ['Manifest']) for layout in FLAT_LAYOUTS] +
    list(itertools.chain.from_iterable(
        [(layout, '', False, ['Manifest']),
         (layout, '', True, ['Manifest', 'sub/Manifest']),
         (layout, 'sub', False, ['Manifest', 'sub/Manifest']),
         ] for layout in SUB_LAYOUTS)) +
    [(BasicTestLayout, 'sub/test', False, ['Manifest', 'sub/Manifest']),
     (BasicTestLayout, 'sub/deeper/test', False,
      ['Manifest', 'sub/Manifest', 'sub/deeper/Manifest']),
     (BasicTestLayout, '', True,
      ['Manifest', 'other/Manifest', 'sub/Manifest',
       'sub/deeper/Manifest']),
     (BasicTestLayout, 'sub', True,
      ['Manifest', 'sub/Manifest', 'sub/deeper/Manifest']),
     (BasicTestLayout, 'sub/test', True, ['Manifest', 'sub/Manifest']),
     (MultiManifestLayout, 'sub', False, ['Manifest',
                                          'sub/Manifest.a',
                                          'sub/Manifest.b']),
     (MultiManifestLayout, '', True, ['Manifest', 'sub/Manifest.a',
                                      'sub/Manifest.b']),
     (MultiTopManifestLayout, '', False, ['Manifest',
                                          'Manifest.a',
                                          'Manifest.b']),
     (MultiTopManifestLayout, 'sub', False, ['Manifest',
                                             'Manifest.a',
                                             'Manifest.b',
                                             'sub/Manifest']),
     (MultiTopManifestLayout, '', True, ['Manifest',
                                         'Manifest.a',
                                         'Manifest.b',
                                         'sub/Manifest']),
     (CompressedTopManifestLayout, None, False, ['Manifest.gz']),
     (CompressedSubManifestLayout, 'sub', False, ['Manifest',
                                                  'sub/Manifest.gz']),
     (CompressedSubManifestLayout, '', True, ['Manifest',
                                              'sub/Manifest.gz']),
     (CompressedManifestSortLayout, None, False, ['Manifest.gz']),
     (CompressedManifestSortLayout, 'a', False, ['Manifest.gz',
                                                 'a/Manifest']),
     (CompressedManifestSortLayout, '', True, ['Manifest.gz',
                                               'a/Manifest']),
     (NestedManifestLayout, '', True, ['Manifest',
                                       'a/Manifest',
                                       'a/x/Manifest',
                                       'a/z/Manifest',
                                       'b/Manifest',
                                       ]),
     (AddToMultiManifestLayout, 'a', False, ['Manifest',
                                             'a/Manifest.a',
                                             'a/Manifest.b']),
     (AddToMultiManifestLayout, '', True, ['Manifest',
                                           'a/Manifest.a',
                                           'a/Manifest.b']),
     ])
def test_load_manifests(layout_factory, layout, path, recursive,
                        expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    assert list(m.loaded_manifests) == [layout.TOP_MANIFEST]
    if path is not None:
        m.load_manifests_for_path(path, recursive=recursive)
    lfunc = sorted if recursive else list
    assert lfunc(m.loaded_manifests) == expected


@pytest.mark.parametrize(
    'layout,path,recursive,diff',
    [(SubManifestMismatchLayout, 'a', False, [('__size__', 0, 50)]),
     (SubManifestMismatchLayout, '', True, [('__size__', 0, 50)]),
     ])
def test_load_manifests_raise(layout_factory, layout, path, recursive,
                              diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    assert list(m.loaded_manifests) == [layout.TOP_MANIFEST]
    with pytest.raises(ManifestMismatch) as exc:
        m.load_manifests_for_path(path, recursive=recursive)
    assert exc.value.diff == diff


@pytest.mark.parametrize(
    'layout,path,recursive,expected',
    [(BasicTestLayout, 'sub/deeper', False, ['sub/deeper', 'sub', '']),
     (BasicTestLayout, 'other', True, ['other', '']),
     (BasicTestLayout, 'sub', True, ['sub/deeper', 'sub', '']),
     (CompressedManifestSortLayout, '', True, ['a', '']),
     ])
def test__iter_manifests_for_path(layout_factory, layout, path,
                                  recursive, expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST)
    m.load_manifests_for_path('', recursive=True)
    assert [d for mpath, d, k
            in m._iter_manifests_for_path(path,
                                          recursive=recursive
                                          )] == expected


def get_entry(entry):
    if entry is not None:
        if entry.tag == 'TIMESTAMP':
            return (entry.tag, entry.ts)
        elif entry.tag == 'IGNORE':
            return (entry.tag, entry.path)
        return (entry.tag, entry.path, sorted(entry.checksums))


@pytest.mark.parametrize(
    'layout,preload_paths,expected',
    [(BasicTestLayout, None,
      ('TIMESTAMP', datetime.datetime(2017, 1, 1, 1, 1, 1))),
     # TIMESTAMP is valid only in top-level Manifest
     (SubTimestampLayout, None, None),
     (SubTimestampLayout, 'sub', None),
     (MultiTopManifestLayout, None,
      ('TIMESTAMP', datetime.datetime(2017, 1, 1, 1, 1, 1))),
     ])
def test_find_timestamp(layout_factory, layout, preload_paths, expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if preload_paths is not None:
        m.load_manifests_for_path(preload_paths)
    assert get_entry(m.find_timestamp()) == expected


@pytest.mark.parametrize(
    'layout',
    [BasicTestLayout,
     DuplicateEntryLayout,
     ])
def test_set_timestamp(layout_factory, layout):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    m.set_timestamp(datetime.datetime(2010, 7, 7, 7, 7, 7))
    assert (get_entry(m.find_timestamp()) ==
            ('TIMESTAMP', datetime.datetime(2010, 7, 7, 7, 7, 7)))
    assert len([x for x
                in m.loaded_manifests['Manifest'].entries
                if x.tag == 'TIMESTAMP']) == 1


@pytest.mark.parametrize(
    'layout,path,expected',
    [(layout, layout.FILENAME, ('DATA', layout.FILENAME, ['MD5']))
     for layout in (FilenameWhitespaceLayout,
                    FilenameBackslashLayout,
                    )] +
    [(BasicTestLayout, 'test', None),
     (BasicTestLayout, 'sub/test', None),
     (BasicTestLayout, 'sub/deeper/test', ('DATA', 'test', ['MD5'])),
     (DuplicateEntryLayout, 'test', ('DATA', 'test', ['MD5'])),
     (DuplicateEntryInSubManifestLayout, 'sub/test',
      ('DATA', 'test', ['MD5'])),
     (DuplicateEbuildEntryLayout, 'test.ebuild',
      ('DATA', 'test.ebuild', ['MD5'])),
     (DuplicateAuxEntryLayout, 'files/test.patch',
      ('DATA', 'files/test.patch', ['MD5'])),
     (DisjointHashSetEntryLayout, 'test',
      ('DATA', 'test', ['MD5'])),
     (IncompatibleTypeLayout, 'metadata.xml',
      ('DATA', 'metadata.xml', ['MD5'])),
     (MismatchedSizeLayout, 'test',
      ('DATA', 'test', ['MD5'])),
     (MismatchedChecksumLayout, 'test',
      ('DATA', 'test', ['MD5'])),
     (IgnoreEntryLayout, 'foo', ('IGNORE', 'foo')),
     (IgnoreEntryLayout, 'bar', ('IGNORE', 'bar')),
     (IgnoreEntryLayout, 'bar/baz', ('IGNORE', 'bar')),
     (CompressedTopManifestLayout, 'test', ('DATA', 'test', ['MD5'])),
     (CompressedSubManifestLayout, 'sub/test',
      ('DATA', 'test', ['MD5'])),
     ])
def test_find_path_entry(layout_factory, layout, path, expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    assert get_entry(m.find_path_entry(path)) == expected


@pytest.mark.parametrize(
    'filename,relpath,expected',
    [('topdistfile-1.txt', '', 'topdistfile-1.txt'),
     ('subdistfile-1.txt', '', None),
     ('topdistfile-1.txt', 'file', 'topdistfile-1.txt'),
     ('subdistfile-1.txt', 'file', None),
     ('topdistfile-1.txt', 'sub', 'topdistfile-1.txt'),
     ('subdistfile-1.txt', 'sub', 'subdistfile-1.txt'),
     ('topdistfile-1.txt', 'sub/', 'topdistfile-1.txt'),
     ('subdistfile-1.txt', 'sub/', 'subdistfile-1.txt'),
     ('topdistfile-1.txt', 'sub/file', 'topdistfile-1.txt'),
     ('subdistfile-1.txt', 'sub/file', 'subdistfile-1.txt'),
     ])
def test_find_dist_entry(layout_factory, filename, relpath, expected):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / 'Manifest')
    if expected is not None:
        expected = ('DIST', expected, ['MD5'])
    assert get_entry(m.find_dist_entry(filename, relpath)) == expected


COMMON_VERIFY_PATH_VARIANTS = [
    # layout, path, expected, diff
    (BasicTestLayout, 'sub/Manifest', True, []),
    (BasicTestLayout, 'sub/deeper/test', True, []),
    (BasicTestLayout, 'sub/deeper/nonexist', True, []),
    (BasicTestLayout, 'sub/stray', False, [('__exists__', False, True)]),
    (MultiManifestLayout, 'sub/foo', False, [('__size__', 32, 16)]),
    (DuplicateEntryLayout, 'test', True, []),
    (DuplicateManifestAsDataEntryLayout, 'sub/Manifest', True, []),
    (DuplicateEntryInSubManifestLayout, 'sub/test', True, []),
    (DuplicateEbuildEntryLayout, 'test.ebuild', True, []),
    (DuplicateAuxEntryLayout, 'files/test.patch', True, []),
    (DisjointHashSetEntryLayout, 'test', False,
     [('MD5',
       '9e107d9d372bb6826bd81d3542a419d6',
       'd41d8cd98f00b204e9800998ecf8427e'),
      ]),
    (DirForFileLayout, 'test', False,
     [('__type__', 'regular file', 'directory')]),
    (CompressedTopManifestLayout, 'test', True, []),
    (CompressedSubManifestLayout, 'sub/test', True, []),
    (MismatchedFileLayout, 'test', False,
     [('MD5',
       '5f8db599de986fab7a21625b7916589c',
       '6f8db599de986fab7a21625b7916589c')]),
    (UnknownHashLayout, 'test', True, []),
]


@pytest.mark.parametrize('layout,path,expected,diff',
                         COMMON_VERIFY_PATH_VARIANTS)
def test_verify_path(layout_factory, layout, path, expected, diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    assert m.verify_path(path) == (expected, diff)


@pytest.mark.parametrize('layout, path,expected,diff',
                         COMMON_VERIFY_PATH_VARIANTS)
def test_assert_path_verifies(layout_factory, layout, path, expected, diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if expected:
        m.assert_path_verifies(path)
    else:
        with pytest.raises(ManifestMismatch) as exc:
            m.assert_path_verifies(path)
        assert exc.value.path == path
        assert exc.value.diff == diff


@pytest.mark.parametrize(
    'layout,path,only_types,expected',
    [(BasicTestLayout, '', None,
      {'other': {'Manifest': ('MANIFEST', 'other/Manifest', ['MD5'])},
       'sub': {'Manifest': ('MANIFEST', 'sub/Manifest', ['MD5'])},
       'sub/deeper': {'Manifest': ('MANIFEST', 'deeper/Manifest', ['MD5']),
                      'test': ('DATA', 'test', ['MD5']),
                      },
       }),
     (BasicTestLayout, '', 'MANIFEST',
      {'other': {'Manifest': ('MANIFEST', 'other/Manifest', ['MD5'])},
       'sub': {'Manifest': ('MANIFEST', 'sub/Manifest', ['MD5'])},
       'sub/deeper': {'Manifest': ('MANIFEST', 'deeper/Manifest', ['MD5'])},
       }),
     (BasicTestLayout, '', 'DIST',
      {'': {'subdistfile-1.txt': ('DIST', 'subdistfile-1.txt', ['MD5']),
            'topdistfile-1.txt': ('DIST', 'topdistfile-1.txt', ['MD5']),
            },
       }),
     (BasicTestLayout, 'sub', None,
      {'sub': {'Manifest': ('MANIFEST', 'sub/Manifest', ['MD5'])},
       'sub/deeper': {'Manifest': ('MANIFEST', 'deeper/Manifest', ['MD5']),
                      'test': ('DATA', 'test', ['MD5']),
                      },
       }),
     (BasicTestLayout, 'sub', 'MANIFEST',
      {'sub': {'Manifest': ('MANIFEST', 'sub/Manifest', ['MD5'])},
       'sub/deeper': {'Manifest': ('MANIFEST', 'deeper/Manifest', ['MD5'])},
       }),
     (BasicTestLayout, 'non-existing', None, {}),
     (DuplicateEntryLayout, '', None,
      {'': {'test': ('DATA', 'test', ['MD5'])}}),
     (DuplicateEntryInSubManifestLayout, '', None,
      {'sub': {'Manifest': ('MANIFEST', 'sub/Manifest', ['MD5']),
               'test': ('DATA', 'sub/test', ['MD5']),
               },
       }),
     (DuplicateManifestAsDataEntryLayout, '', None,
      {'sub': {'Manifest': ('DATA', 'sub/Manifest', ['MD5']),
               'test': ('DATA', 'test', ['MD5']),
               }}),
     (DuplicateEbuildEntryLayout, '', None,
      {'': {'test.ebuild': ('EBUILD', 'test.ebuild', ['MD5'])}}),
     (DuplicateEbuildEntryLayout, '', 'DATA',
      {'': {'test.ebuild': ('DATA', 'test.ebuild', ['MD5'])}}),
     (DuplicateAuxEntryLayout, '', None,
      {'files': {'test.patch': ('AUX', 'files/test.patch', ['MD5'])}}),
     (DuplicateAuxEntryLayout, '', 'DATA',
      {'files': {'test.patch': ('DATA', 'files/test.patch', ['MD5'])}}),
     (DisjointHashSetEntryLayout, '', None,
      {'': {'test': ('DATA', 'test', ['MD5', 'SHA1'])}}),
     (IncompatibleTypeLayout, '', 'DATA',
      {'': {'metadata.xml': ('DATA', 'metadata.xml', ['MD5'])}}),
     (IncompatibleTypeLayout, '', 'MISC',
      {'': {'metadata.xml': ('MISC', 'metadata.xml', ['MD5'])}}),
     (UnknownHashLayout, '', None,
      {'': {'test': ('DATA', 'test', ['MD5', 'X-UNKNOWN'])}}),
     ])
def test_get_file_entry_dict(layout_factory, layout, path, only_types,
                             expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if only_types is not None:
        only_types = [only_types]
    entries = m.get_file_entry_dict(path, only_types=only_types)
    assert ({subdir: {k: get_entry(v) for k, v in files.items()}
             for subdir, files in entries.items()
             } == expected)


@pytest.mark.parametrize(
    'layout,path,only_types,diff',
    [(IncompatibleTypeLayout, '', None, [('__type__', 'DATA', 'MISC')]),
     (MismatchedSizeLayout, '', None, [('__size__', 0, 32)]),
     (MismatchedChecksumLayout, '', None,
      [('MD5',
        'd41d8cd98f00b204e9800998ecf8427e',
        '9e107d9d372bb6826bd81d3542a419d6')]),
     ])
def test_get_file_entry_dict_incompatible(layout_factory, layout, path,
                                          only_types, diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if only_types is not None:
        only_types = [only_types]
    with pytest.raises(ManifestIncompatibleEntry) as exc:
        m.get_file_entry_dict(path, only_types=only_types)
    assert exc.value.diff == diff


@pytest.mark.parametrize(
    'layout,path,expected',
    [(BasicTestLayout, '',
      {'other/Manifest': ('Manifest', 'MANIFEST', 'other/Manifest',
                          ['MD5']),
       'sub/Manifest': ('Manifest', 'MANIFEST', 'sub/Manifest', ['MD5']),
       'sub/deeper/Manifest': ('sub/Manifest', 'MANIFEST',
                               'deeper/Manifest', ['MD5']),
       'sub/deeper/test': ('sub/deeper/Manifest', 'DATA', 'test',
                           ['MD5']),
       }),
     (BasicTestLayout, 'sub',
      {'sub/Manifest': ('Manifest', 'MANIFEST', 'sub/Manifest', ['MD5']),
       'sub/deeper/Manifest': ('sub/Manifest', 'MANIFEST',
                               'deeper/Manifest', ['MD5']),
       'sub/deeper/test': ('sub/deeper/Manifest', 'DATA', 'test',
                           ['MD5']),
       }),
     (BasicTestLayout, 'non-existing', {}),
     (DuplicateEntryLayout, '',
      {'test': ('Manifest', 'DATA', 'test', ['MD5'])}),
     (DuplicateEntryInSubManifestLayout, '',
      {'sub/Manifest': ('Manifest', 'MANIFEST', 'sub/Manifest', ['MD5']),
       'sub/test': ('sub/Manifest', 'DATA', 'test', ['MD5']),
       }),
     (DisjointHashSetEntryLayout, '',
      {'test': ('Manifest', 'DATA', 'test', ['MD5', 'SHA1'])}),
     (MismatchedSizeLayout, '',
      {'test': ('Manifest', 'DATA', 'test', ['MD5'])}),
     (MismatchedChecksumLayout, '',
      {'test': ('Manifest', 'DATA', 'test', ['MD5'])}),
     ])
def test_get_deduplicated_file_entry_dict_for_update(layout_factory,
                                                     layout,
                                                     path,
                                                     expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    entries = m.get_deduplicated_file_entry_dict_for_update(path)
    assert {k: (v[0],) + get_entry(v[1])
            for k, v in entries.items()} == expected


@pytest.mark.parametrize(
    'layout,path,diff',
    [(IncompatibleTypeLayout, '', [('__type__', 'DATA', 'MISC')]),
     ])
def test_get_deduplicated_file_entry_dict_incompatible(layout_factory,
                                                       layout,
                                                       path,
                                                       diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    with pytest.raises(ManifestIncompatibleEntry) as exc:
        m.get_deduplicated_file_entry_dict_for_update(path)
    assert exc.value.diff == diff


COMMON_DIRECTORY_VERIFICATION_VARIANTS = [
    # layout, path, fail_path, diff
    (BasicTestLayout, 'other', None, []),
    (BasicTestLayout, 'sub', 'sub/stray',
     [('__exists__', False, True)]),
    (DuplicateEntryLayout, '', None, []),
    (DuplicateManifestEntryLayout, '', None, []),
    (DuplicateManifestAsDataEntryLayout, '', None, []),
    (DuplicateEbuildEntryLayout, '', None, []),
    (DuplicateAuxEntryLayout, '', None, []),
    (DisjointHashSetEntryLayout, '', 'test',
     [('MD5',
       '9e107d9d372bb6826bd81d3542a419d6',
       'd41d8cd98f00b204e9800998ecf8427e'),
      ('SHA1',
       '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
       'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
      ]),
    (IgnoreEntryLayout, '', None, []),
    (MiscEntryLayout, '', 'metadata.xml',
     [('__exists__', True, False)]),
    (CrossDeviceIgnoreLayout, '', None, []),
    (DotFileLayout, '', None, []),
    (DirForFileLayout, '', 'test',
     [('__type__', 'regular file', 'directory')]),
    (CompressedSubManifestLayout, '', None, []),
    (FilenameWhitespaceLayout, '', None, []),
    (FilenameBackslashLayout, '', None, []),
    (NonexistingDirectoryLayout, '', 'sub/test',
     [('__exists__', True, False)]),
    (MismatchedFileLayout, '', 'test',
     [('MD5',
       '5f8db599de986fab7a21625b7916589c',
       '6f8db599de986fab7a21625b7916589c')]),
    (UnknownHashLayout, '', None, []),
]


@pytest.mark.parametrize(
    'layout,path,fail_handler,expected,fail_path,diff',
    [(layout, path, None,
      True if fail_path is None else ManifestMismatch,
      fail_path, diff)
     for layout, path, fail_path, diff
     in COMMON_DIRECTORY_VERIFICATION_VARIANTS] +
    [(BasicTestLayout, 'sub', lambda e: True, True, None, []),
     (BasicTestLayout, 'sub', lambda e: False, False, None, []),
     (IncompatibleTypeLayout, '', None, ManifestIncompatibleEntry, None,
      [('__type__', 'DATA', 'MISC')]),
     (MismatchedSizeLayout, '', None, ManifestIncompatibleEntry, None,
      [('__size__', 0, 32)]),
     (MismatchedChecksumLayout, '', None, ManifestIncompatibleEntry,
      None,
      [('MD5',
        'd41d8cd98f00b204e9800998ecf8427e',
        '9e107d9d372bb6826bd81d3542a419d6')]),
     (MiscEntryLayout, '', lambda e: True, True, None, []),
     (CrossDeviceLayout, '', None, ManifestCrossDevice, None, []),
     (CrossDeviceLayout, '', lambda e: True, ManifestCrossDevice, None,
      []),
     (CrossDeviceLayout, 'sub', None, ManifestCrossDevice, None, []),
     (CrossDeviceEmptyLayout, '', None, ManifestCrossDevice, None, []),
     (CrossDeviceEmptyLayout, '', lambda e: True, ManifestCrossDevice,
      None, []),
     (CrossDeviceEmptyLayout, 'sub', None, ManifestCrossDevice, None,
      []),
     (CrossDeviceIgnoreLayout, 'sub', None, ManifestCrossDevice, None,
      []),
     (UnreadableDirLayout, '', None, PermissionError, None, []),
     (UnreadableDirLayout, '', lambda e: False, PermissionError, None,
      []),
     (CompressedTopManifestLayout, '', None, True, None, []),
     (NonexistingDirectoryLayout, '', lambda e: False, False, None, []),
     (SymlinkLoopLayout, '', None, ManifestSymlinkLoop, None, []),
     (SymlinkLoopLayout, '', lambda e: False, ManifestSymlinkLoop, None,
      []),
     (SymlinkLoopIgnoreLayout, '', None, True, None, []),
     (UnknownHashOnlyLayout, '', None, ManifestNoSupportedHashes, None, []),
     ])
def test_assert_directory_verifies(layout_factory, layout, path, fail_handler,
                                   expected, fail_path, diff):
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if expected is ManifestMismatch:
        with pytest.raises(expected) as exc:
            m.assert_directory_verifies(path)
        assert (exc.value.path, exc.value.diff) == (fail_path, diff)
    elif expected is ManifestIncompatibleEntry:
        with pytest.raises(expected) as exc:
            m.assert_directory_verifies(path)
        assert exc.value.diff == diff
    elif type(expected) is type and issubclass(expected, Exception):
        with pytest.raises(expected) as exc:
            m.assert_directory_verifies(path)
    else:
        kwargs = {}
        if fail_handler is not None:
            kwargs['fail_handler'] = fail_handler
        assert m.assert_directory_verifies(path, **kwargs) == expected


@pytest.mark.parametrize(
    'layout,path,args,expected',
    [(layout, path, '',
      None if fail_path is None
      else str(ManifestMismatch(fail_path, None, diff)))
     for layout, path, fail_path, diff
     in COMMON_DIRECTORY_VERIFICATION_VARIANTS] +
    [(BasicTestLayout, 'sub', '--keep-going',
      str(ManifestMismatch('sub/stray', None, []))),
     (BasicTestLayout, 'other', '--require-signed-manifest',
      'is not OpenPGP signed'),
     (IncompatibleTypeLayout, '', '',
      str(ManifestIncompatibleEntry(ManifestPathEntry('metadata.xml'),
                                    None,
                                    [('__type__', 'DATA', 'MISC')]))),
     (MismatchedSizeLayout, '', '',
      str(ManifestIncompatibleEntry(ManifestPathEntry('test'),
                                    None,
                                    [('__size__', 0, 32)]))),
     (MismatchedChecksumLayout, '', '',
      str(ManifestIncompatibleEntry(ManifestPathEntry('test'),
                                    None,
                                    [('MD5',
                                      'd41d8cd98f00b204e9800998ecf8427e',
                                      '9e107d9d372bb6826bd81d3542a419d6'
                                      )]))),
     (CrossDeviceLayout, '', '',
      str(ManifestCrossDevice('<path>')).split('<path>', 1)[1]),
     (CrossDeviceEmptyLayout, '', '',
      str(ManifestCrossDevice('<path>')).split('<path>', 1)[1]),
     (SymlinkLoopLayout, '', '',
      str(ManifestSymlinkLoop('<path>')).split('<path>', 1)[1]),
     (SymlinkLoopIgnoreLayout, '', '', None),
     (UnknownHashOnlyLayout, '', '',
      str(ManifestNoSupportedHashes("<path>", ManifestFileEntry(
            "", 0, {"X-UNKNOWN": ""}))).split("<path>", 1)[1]),
     ])
def test_cli_verify(layout_factory, caplog, layout, path, args, expected):
    tmp_path = layout_factory.create(layout, readonly=True)
    expected_retcode = 0 if expected is None else 1
    assert gemato.cli.main(['gemato', 'verify', '-x'] + args.split() +
                           [str(tmp_path / path)]) == expected_retcode
    if expected is not None:
        assert expected in caplog.text


@pytest.mark.parametrize(
    'layout,relpath',
    [(BasicTestLayout, path) for path in BasicTestLayout.MANIFESTS] +
    [(CompressedTopManifestLayout, 'Manifest.gz'),
     ])
def test_save_manifest(layout_factory, layout, relpath):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    m.load_manifest(relpath)
    os.remove(tmp_path / relpath)
    m.save_manifest(relpath)
    with open_potentially_compressed_path(tmp_path / relpath, 'r') as f:
        assert f.read() == layout.MANIFESTS[relpath].lstrip()


@pytest.mark.parametrize(
    'layout,force,sort,expected_attr',
    [(BasicTestLayout, False, False, 'MANIFESTS'),
     (BasicTestLayout, True, False, 'MANIFESTS_REWRITTEN'),
     (BasicTestLayout, True, True, 'MANIFESTS_SORTED'),
     (FilenameWhitespaceLayout, True, False, 'MANIFESTS_REWRITTEN'),
     (FilenameBackslashLayout, True, False, 'MANIFESTS_REWRITTEN'),
     ])
def test_save_manifests_unmodified(layout_factory, layout, force, sort,
                                   expected_attr):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if not force:
        m.load_manifests_for_path('', recursive=True)
    m.save_manifests(force=force, sort=sort)
    output = {}
    for relpath in layout.MANIFESTS:
        with open(tmp_path / relpath) as f:
            output[relpath] = f.read()
    assert output == getattr(layout, expected_attr)


@pytest.mark.parametrize(
    'new_entry_type,manifest_checksum',
    [('DATA', '27b043ae4e184ad25aec6e793f3a23f4'),
     ('MANIFEST', '3db86d6c89178496902a012ae562f4f4'),
     ('MISC', '74f04c5178fc1d27bb83871bff88caf1'),
     ('EBUILD', '993f2e85ab23b5fe902b089584ca829e'),
     ('AUX', None),
     ('DIST', None),
     ('IGNORE', None),
     ])
def test_update_entry_for_path_types(layout_factory,
                                     new_entry_type,
                                     manifest_checksum):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    if manifest_checksum is None:
        with pytest.raises(AssertionError):
            m.update_entry_for_path('sub/stray',
                                    hashes=['SHA256', 'SHA512'],
                                    new_entry_type=new_entry_type)
    else:
        m.update_entry_for_path('sub/stray',
                                hashes=['SHA256', 'SHA512'],
                                new_entry_type=new_entry_type)
        new_entry = m.find_path_entry('sub/stray')
        assert get_entry(new_entry) == (new_entry_type, 'stray',
                                        ['SHA256', 'SHA512'])
        m.save_manifests()

        output = {}
        for relpath in layout.MANIFESTS:
            with open(tmp_path / relpath) as f:
                output[relpath] = f.read()
        expected = dict(layout.MANIFESTS)
        expected['Manifest'] = (
            expected['Manifest'].lstrip()
            .replace('128 MD5 30fd28b98a23031c72793908dd35c530',
                     f'{344 + len(new_entry_type)} MD5 {manifest_checksum}'))
        expected['sub/Manifest'] = (
            expected['sub/Manifest'].lstrip() +
            f'{new_entry_type} stray 0 SHA256 '
            f'e3b0c44298fc1c149afbf4c8996fb924'
            f'27ae41e4649b934ca495991b7852b855 SHA512 '
            f'cf83e1357eefb8bdf1542850d66d8007'
            f'd620e4050b5715dc83f4a921d36ce9ce'
            f'47d0d13c5d85f2b0ff8318d2877eec2f'
            f'63b931bd47417a81a538327af927da3e\n')
        assert output == expected
        m.assert_directory_verifies()

        if new_entry_type == 'MANIFEST':
            assert 'sub/stray' in m.loaded_manifests


def test_update_entry_for_path_no_hash_specified(layout_factory):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    with pytest.raises(AssertionError):
        m.update_entry_for_path('sub/stray')


@pytest.mark.parametrize(
    'layout,ctor,func,path,call,save,manifest_update',
    [(BasicTestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/stray',
      None,
      None,
      {'Manifest': BasicTestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('128 MD5 30fd28b98a23031c72793908dd35c530',
                '186 SHA1 2b89b8bc8db9cec987beeb7f08f574f1766e6b06'),
       'sub/Manifest': BasicTestLayout.MANIFESTS['sub/Manifest']
       .lstrip() +
       'DATA stray 0 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709\n',
       }),
     (BasicTestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/stray',
      ['MD5'],
      None,
      {'Manifest': BasicTestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('128 MD5 30fd28b98a23031c72793908dd35c530',
                '177 SHA1 d6ecf169c7c4e951d5c633c8e0debe5df1a8c0aa'),
       'sub/Manifest': BasicTestLayout.MANIFESTS['sub/Manifest']
       .lstrip() + 'DATA stray 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (BasicTestLayout,
      None,
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/stray',
      ['SHA1'],
      None,
      {'Manifest': BasicTestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('128 MD5 30fd28b98a23031c72793908dd35c530',
                '186 MD5 52e5664c2b12561cf296549395c0462a'),
       'sub/Manifest': BasicTestLayout.MANIFESTS['sub/Manifest']
       .lstrip() +
       'DATA stray 0 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709\n',
       }),
     (BasicTestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      # this rehashes all files
      BasicTestLayout.MANIFESTS_SHA1),
     (BasicTestLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      ['SHA1'],
      {'Manifest': BasicTestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('128 MD5 30fd28b98a23031c72793908dd35c530',
                '177 SHA1 d6ecf169c7c4e951d5c633c8e0debe5df1a8c0aa'),
       'sub/Manifest': BasicTestLayout.MANIFESTS['sub/Manifest']
       .lstrip() + 'DATA stray 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (BasicTestLayout,
      ['SHA256'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      ['SHA1'],
      None,
      # ctor is used for Manifests that are edited, call is used
      # for everything else
      # TODO: does this behavior really make sense?
      {'Manifest': 'TIMESTAMP 2017-01-01T01:01:01Z\n'
                   'MANIFEST sub/Manifest 221 SHA256 '
                   '0c4f14d1e07eb2762ca9afec0d64d8a9'
                   'd65e3d99b5700fd2779f3b2641d2807a\n'
                   'MANIFEST other/Manifest 0 SHA1 '
                   'da39a3ee5e6b4b0d3255bfef95601890afd80709\n'
                   'DIST topdistfile-1.txt 0 MD5 '
                   'd41d8cd98f00b204e9800998ecf8427e\n',
       'sub/Manifest': 'MANIFEST deeper/Manifest 58 SHA256 '
                       '87d10bbc90d9d7838141dd2d50a58760'
                       '20a182dd950ef551b7f689bc178d6e6c\n'
                       'DIST subdistfile-1.txt 0 MD5 '
                       'd41d8cd98f00b204e9800998ecf8427e\n'
                       'DATA stray 0 SHA1 '
                       'da39a3ee5e6b4b0d3255bfef95601890afd80709\n',
       'sub/deeper/Manifest': 'DATA test 0 SHA1 '
                              'da39a3ee5e6b4b0d3255'
                              'bfef95601890afd80709\n',
       }),
     (MultiManifestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/foo',
      None,
      None,
      {'Manifest': MultiManifestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('50 MD5 33fd9df6d410a93ff859d75e088bde7e',
                '58 SHA1 dc62bbde3db6e82aea65c3643ae0d6be50aa8a53'),
       'sub/Manifest.a': 'DATA foo 16 '
       'SHA1 deed2a88e73dccaa30a9e6e296f62be238be4ade\n',
       }),
     (MultiManifestLayout,
      None,
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/foo',
      ['SHA1'],
      None,
      {'Manifest': MultiManifestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('50 MD5 33fd9df6d410a93ff859d75e088bde7e',
                '58 MD5 094185d851bf9a700889e37a46700420'),
       'sub/Manifest.a': 'DATA foo 16 '
       'SHA1 deed2a88e73dccaa30a9e6e296f62be238be4ade\n',
       }),
     (MultiManifestLayout,
      None,
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/foo',
      ['MD5'],
      ['SHA1'],
      {'Manifest': MultiManifestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('50 MD5 33fd9df6d410a93ff859d75e088bde7e',
                '49 SHA1 08a3eac069b8b442513016d60a3da7288c4ea821'),
       'sub/Manifest.a': 'DATA foo 16 '
       'MD5 abeac07d3c28c1bef9e730002c753ed4\n',
       }),
     (MultiManifestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/foo',
      None,
      None,
      {'Manifest': MultiManifestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('50 MD5 33fd9df6d410a93ff859d75e088bde7e',
                '58 SHA1 dc62bbde3db6e82aea65c3643ae0d6be50aa8a53'),
       'sub/Manifest.a': 'DATA foo 16 '
       'SHA1 deed2a88e73dccaa30a9e6e296f62be238be4ade\n',
       }),
     (MultiManifestLayout,
      ['SHA1'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/foo',
      ['MD5'],
      None,
      {'Manifest': MultiManifestLayout.MANIFESTS['Manifest'].lstrip()
       .replace('50 MD5 33fd9df6d410a93ff859d75e088bde7e',
                '49 SHA1 08a3eac069b8b442513016d60a3da7288c4ea821'),
       'sub/Manifest.a': 'DATA foo 16 '
       'MD5 abeac07d3c28c1bef9e730002c753ed4\n',
       }),
     (DuplicateAuxEntryLayout,
      None,
      ManifestRecursiveLoader.update_entry_for_path,
      'files/test.patch',
      None,
      None,
      {'Manifest': DuplicateAuxEntryLayout.MANIFESTS['Manifest']
       .splitlines()[1] + '\n',
       }),
     (DuplicateAuxEntryLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest': DuplicateAuxEntryLayout.MANIFESTS['Manifest']
       .splitlines()[1] + '\n',
       }),
     (DisjointHashSetEntryLayout,
      None,
      ManifestRecursiveLoader.update_entry_for_path,
      'test',
      None,
      None,
      {'Manifest': 'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (DisjointHashSetEntryLayout,
      ['SHA256'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest': 'DATA test 0 SHA256 '
       'e3b0c44298fc1c149afbf4c8996fb924'
       '27ae41e4649b934ca495991b7852b855\n',
       }),
     (MiscEntryLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entry_for_path,
      'metadata.xml',
      None,
      None,
      {'Manifest': '',
       }),
     (MiscEntryLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest': '',
       }),
     (CrossDeviceIgnoreLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {}),
     (DotFileLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {}),
     (CompressedSubManifestLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'sub/Manifest.gz': 'DATA test 0 MD5 '
       'd41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (CompressedManifestSortLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest.gz':
       'MANIFEST a/Manifest 50 MD5 8ee2fce40e6e6cc2b5de5c91d416e9f3\n',
       'a/Manifest':
       'DATA stray 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (StrayManifestLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest':
       'MANIFEST sub/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n',
       'sub/Manifest':
       StrayManifestLayout.MANIFESTS['sub/Manifest'].lstrip()
       }),
     (FilenameWhitespaceLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {}),
     (FilenameBackslashLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {}),
     (NestedManifestLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest':
       'MANIFEST a/Manifest 220 MD5 e85fbbce600362ab3378ebd7a2bc06db\n'
       'MANIFEST b/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n'
       'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       'a/Manifest':
       'MANIFEST x/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n'
       'MANIFEST z/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n'
       'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n'
       'DATA y/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       'a/x/Manifest':
       'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       'a/z/Manifest':
       'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       'b/Manifest':
       'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (SubManifestMismatchLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest':
       'MANIFEST a/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a\n',
       }),
     (SubManifestMismatchLayout,
      ["MD5"],
      ManifestRecursiveLoader.update_entry_for_path,
      "a/Manifest",
      None,
      None,
      {"Manifest":
       "MANIFEST a/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a\n",
       }),
     (SubManifestMismatchLayout,
      ["MD5"],
      ManifestRecursiveLoader.update_entry_for_path,
      "a/test",
      None,
      None,
      {"Manifest":
       "MANIFEST a/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n",
       "a/Manifest":
       "DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n",
       }),
     (NonexistingDirectoryLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entry_for_path,
      'sub/test',
      None,
      None,
      {'Manifest': '',
       }),
     (NonexistingDirectoryLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest': '',
       }),
     (SymlinkLoopIgnoreLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {}),
     (MismatchedFileLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entry_for_path,
      'test',
      None,
      None,
      {'Manifest': 'DATA test 11 MD5 6f8db599de986fab7a21625b7916589c\n',
       }),
     (MismatchedFileLayout,
      ['MD5'],
      ManifestRecursiveLoader.update_entries_for_directory,
      '',
      None,
      None,
      {'Manifest': 'DATA test 11 MD5 6f8db599de986fab7a21625b7916589c\n',
       }),
     ])
def test_update_entry_hash_specs(layout_factory, layout, ctor, func, path,
                                 call, save, manifest_update):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=ctor,
                                allow_xdev=False)
    func(m, path, hashes=call)
    m.save_manifests(hashes=save)

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    expected = dict(layout.MANIFESTS)
    expected.update(manifest_update)
    assert output == expected
    m.assert_directory_verifies()


def test_update_entry_hash_stray_compressed(layout_factory):
    layout = StrayCompressedManifestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=["MD5"],
                                allow_xdev=False)
    ManifestRecursiveLoader.update_entries_for_directory(m, "")
    m.save_manifests()

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    hashes = hash_path(tmp_path / "sub/Manifest.gz", ["__size__", "md5"])
    expected = dict(layout.MANIFESTS)
    expected.update(
        {"Manifest": f"MANIFEST sub/Manifest.gz {hashes['__size__']} "
         f"MD5 {hashes['md5']}\n",
         "sub/Manifest.gz":
         StrayCompressedManifestLayout.MANIFESTS["sub/Manifest.gz"].lstrip()
         })
    assert output == expected
    m.assert_directory_verifies()


@pytest.mark.parametrize(
    'layout,manifest_update',
    [(MultipleStrayFilesLayout,
      {'Manifest': ''.join(f'DATA sub/file.{x} 0 MD5 '
                           f'd41d8cd98f00b204e9800998ecf8427e\n'
                           for x in 'abc'),
       }),
     (StrayInvalidManifestLayout,
      {'Manifest':
       'DATA sub/Manifest 19 MD5 1c0817af3a5def5d5c90b139988727a7\n'
       'DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (StrayInvalidCompressedManifestLayout,
      {'Manifest':
       'DATA sub/Manifest.gz 18 MD5 f937f0ff743477e4f70ef2b79672c9bc\n'
       'DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (StrayInvalidCompressedManifestBz2Layout,
      {'Manifest':
       'DATA sub/Manifest.bz2 18 MD5 f937f0ff743477e4f70ef2b79672c9bc\n'
       'DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (StrayInvalidCompressedManifestLzmaLayout,
      {'Manifest':
       'DATA sub/Manifest.lzma 18 MD5 f937f0ff743477e4f70ef2b79672c9bc\n'
       'DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (StrayInvalidCompressedManifestXzLayout,
      {'Manifest':
       'DATA sub/Manifest.xz 18 MD5 f937f0ff743477e4f70ef2b79672c9bc\n'
       'DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     (AddToMultiManifestLayout,
      {'Manifest':
       'DATA b/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n'
       'MANIFEST a/Manifest 46 MD5 dae3736ed4a6d6a3a74aa0af1b063bdf\n'
       'MANIFEST a/Manifest.a 46 MD5 9694e21e0a3f2e49cbc0fc9ab44797e8\n'
       'MANIFEST a/Manifest.b 46 MD5 93f00cb02b04ad2520414af7983ebae7\n',
       'a/Manifest': 'DATA c 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
       }),
     ])
def test_update_entries_unordered(layout_factory, layout,
                                  manifest_update):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)
    m.update_entries_for_directory('')
    m.save_manifests(sort=True, force=True)

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    expected = dict(layout.MANIFESTS)
    expected.update(manifest_update)
    assert output == expected
    m.assert_directory_verifies()


@pytest.mark.parametrize(
    'layout,path,expected,reason',
    [(BasicTestLayout, 'nonexist', ManifestInvalidPath,
      ('__exists__', False)),
     # verify that aux_path does not confuse it
     (DuplicateAuxEntryLayout, 'test.patch', ManifestInvalidPath,
      ('__exists__', False)),
     (PotentialAuxEntryLayout, 'test.patch', ManifestInvalidPath,
      ('__exists__', False)),
     (CrossDeviceLayout, 'sub/version', ManifestCrossDevice, None),
     (DirForFileLayout, 'test', ManifestInvalidPath,
      ('__type__', 'directory')),
     ])
def test_update_entry_raise(layout_factory, layout, path, expected, reason):
    """Test that update_entry_for_path() raises an exception"""
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)
    with pytest.raises(expected) as exc:
        m.update_entry_for_path(path)
    if expected is ManifestInvalidPath:
        assert exc.value.detail == reason


@pytest.mark.parametrize(
    'layout,path',
    [(UnknownHashLayout, 'test'),
     (UnknownHashOnlyLayout, 'test'),
     ])
def test_update_entry_unknown_hash(layout_factory, layout, path):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    with pytest.raises(KeyError):
        m.update_entry_for_path(path)


@pytest.mark.parametrize(
    'layout,path,expected',
    [(BasicTestLayout, 'nonexist', FileNotFoundError),
     (CrossDeviceLayout, '', ManifestCrossDevice),
     (CrossDeviceEmptyLayout, '', ManifestCrossDevice),
     (DirForFileLayout, '', ManifestInvalidPath),
     (UnreadableDirLayout, '', PermissionError),
     (SymlinkLoopLayout, '', ManifestSymlinkLoop),
     ])
def test_update_entries_for_directory_raise(layout_factory, layout, path,
                                            expected):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)
    with pytest.raises(expected):
        m.update_entries_for_directory(path)


def test_update_entry_new_aux(layout_factory):
    layout = PotentialAuxEntryLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)
    m.update_entry_for_path('files/test.patch', new_entry_type='AUX')
    assert (get_entry(m.find_path_entry('files/test.patch')) ==
            ('AUX', 'files/test.patch', ['MD5']))
    m.save_manifests()
    with open(tmp_path / layout.TOP_MANIFEST) as f:
        contents = f.read()
    assert (contents ==
            'AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n')
    m.assert_directory_verifies()


def test_update_entry_and_discard(layout_factory):
    """Test that Manifests are not changed without .save_manifests()"""
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['SHA1'],
                                allow_xdev=False)
    m.update_entry_for_path('sub/stray', hashes=['MD5'])
    del m

    output = {}
    for relpath in layout.MANIFESTS:
        with open(tmp_path / relpath) as f:
            output[relpath] = f.read()
    assert output == layout.MANIFESTS


@pytest.mark.parametrize(
    'layout,args,update,replace_timestamp',
    [(BasicTestLayout,
      '',
      BasicTestLayout.MANIFESTS_SHA1,
      'TIMESTAMP 2017-01-01T01:01:01Z'),
     (DuplicateEntryLayout,
      '',
      {'Manifest':
       DuplicateEntryLayout.MANIFESTS['Manifest'].splitlines()[1] +
       '\nTIMESTAMP\n'
       },
      'TIMESTAMP'),
     (MiscEntryLayout,
      '',
      {'Manifest': 'TIMESTAMP\n'},
      'TIMESTAMP'),
     (CrossDeviceIgnoreLayout,
      '',
      {},
      None),
     (DotFileLayout,
      '',
      {},
      None),
     (StrayManifestLayout,
      '',
      {'Manifest': 'MANIFEST sub/Manifest 58 SHA1 '
       '4b40f4102dd71fb2083ce9a8d8af6d7e49c281c4\n'
       'TIMESTAMP\n',
       'sub/Manifest': 'DATA test 0 SHA1 '
       'da39a3ee5e6b4b0d3255bfef95601890afd80709\n',
       },
      'TIMESTAMP'),
     (FilenameWhitespaceLayout,
      '',
      {'Manifest':
       'DATA \\x20\\x20foo\\x20bar\\x20\\x20 0 SHA1 '
       'da39a3ee5e6b4b0d3255bfef95601890afd80709\n'
       'TIMESTAMP\n',
       },
      'TIMESTAMP'),
     (SymlinkLoopIgnoreLayout,
      '',
      {},
      None),
     (MismatchedFileFutureTimestampLayout,
      '',
      {'Manifest': 'TIMESTAMP\n'
       'DATA test 11 SHA1 661295c9cbf9d6b2f6428414504a8deed3020641\n'
       },
      'TIMESTAMP'),
     (MismatchedFileFutureTimestampLayout,
      '--incremental',
      {},
      'TIMESTAMP'),
     ])
def test_cli_update(layout_factory, layout, args, update,
                    replace_timestamp):
    tmp_path = layout_factory.create(layout)
    assert gemato.cli.main(['gemato', 'update', '-x', '--hashes=SHA1',
                            '--timestamp'] + args.split() +
                           [str(tmp_path)]) == 0

    if replace_timestamp is not None:
        m = gemato.manifest.ManifestFile()
        with open(tmp_path / layout.TOP_MANIFEST) as f:
            m.load(f)
        ts = m.find_timestamp()
        assert ts is not None
        assert ts.ts != datetime.datetime(2017, 1, 1, 1, 1, 1)

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    expected = dict(layout.MANIFESTS)
    expected.update(update)
    if replace_timestamp is not None:
        expected['Manifest'] = expected['Manifest'].replace(
            replace_timestamp, ' '.join(ts.to_list()))
    assert output == expected


@pytest.mark.parametrize(
    'layout,expected',
    [(CrossDeviceLayout,
      str(ManifestCrossDevice('<path>')).split('<path>', 1)[1]),
     (CrossDeviceEmptyLayout,
      str(ManifestCrossDevice('<path>')).split('<path>', 1)[1]),
     (DirForFileLayout,
      str(ManifestInvalidPath('<path>', ('__type__', 'directory')))
      .split('<path>', 1)[1]),
     (SymlinkLoopLayout,
      str(ManifestSymlinkLoop('<path>')).split('<path>', 1)[1]),
     ])
def test_cli_update_fail(layout_factory, caplog, layout, expected):
    tmp_path = layout_factory.create(layout)
    assert gemato.cli.main(['gemato', 'update', '-x', '--hashes=SHA1',
                            '--timestamp', str(tmp_path)]) == 1
    assert expected in caplog.text


COMMON_COMPRESS_VARIANTS = (
    # layout, watermark, compress_format, expected_compressed
    list(itertools.chain.from_iterable(
        [(BasicTestLayout, 0, algo,
          [x for x in BasicTestLayout.MANIFESTS if x != 'Manifest']),
         (BasicTestLayout, 64, algo, ['sub/Manifest']),
         ] for algo in COMPRESSION_ALGOS)) +
    [(CompressedSubManifestLayout, 0, 'gz', ['sub/Manifest']),
     (CompressedSubManifestLayout, 4096, 'gz', []),
     ])


@pytest.mark.parametrize(
    'layout,watermark,compress_format,expected_compressed',
    COMMON_COMPRESS_VARIANTS +
    [(CompressedTopManifestLayout, 0, 'gz', ['Manifest']),
     (CompressedTopManifestLayout, 4096, 'gz', []),
     ])
def test_compress_manifests(layout_factory, layout, watermark,
                            expected_compressed, compress_format):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)
    m.save_manifests(force=True,
                     compress_watermark=watermark,
                     compress_format=compress_format)

    manifests = []
    for dirpath, dirnames, filenames in os.walk(tmp_path):
        for f in filenames:
            if f.startswith('Manifest'):
                manifests.append(
                    os.path.relpath(os.path.join(dirpath, f), tmp_path))
    expected_manifest_basenames = (os.path.splitext(x)[0]
                                   for x in layout.MANIFESTS)
    expected = [(f'{x}.{compress_format}' if x in expected_compressed
                 else x)
                for x in expected_manifest_basenames]
    assert sorted(manifests) == sorted(expected)


@pytest.mark.parametrize(
    'layout,watermark,compress_format,expected_compressed',
    COMMON_COMPRESS_VARIANTS)
def test_cli_compress(layout_factory, layout, watermark,
                      expected_compressed, compress_format):
    tmp_path = layout_factory.create(layout)
    assert gemato.cli.main(['gemato', 'update', '--hashes=MD5',
                            f'--compress-format={compress_format}',
                            f'--compress-watermark={watermark}',
                            '--force-rewrite', str(tmp_path)]) == 0

    manifests = []
    for dirpath, dirnames, filenames in os.walk(tmp_path):
        for f in filenames:
            if f.startswith('Manifest'):
                manifests.append(
                    os.path.relpath(os.path.join(dirpath, f), tmp_path))
    expected_manifest_basenames = (os.path.splitext(x)[0]
                                   for x in layout.MANIFESTS)
    expected = [(f'{x}.{compress_format}' if x in expected_compressed
                 else x)
                for x in expected_manifest_basenames]
    assert sorted(manifests) == sorted(expected)


@pytest.mark.parametrize(
    'layout,expected',
    [(DuplicateEntryLayout,
      DuplicateEntryLayout.MANIFESTS['Manifest'].splitlines()[1] + '\n'
      ),
     (DuplicateManifestEntryLayout,
      DuplicateManifestEntryLayout.MANIFESTS['Manifest'].splitlines()[1]
      + '\n'),
     (DuplicateManifestAsDataEntryLayout,
      DuplicateManifestAsDataEntryLayout.MANIFESTS['Manifest']
      .splitlines()[1] + '\n'),
     (DuplicateEbuildEntryLayout,
      DuplicateEbuildEntryLayout.MANIFESTS['Manifest'].splitlines()[1]
      + '\n'),
     (DuplicateAuxEntryLayout,
      DuplicateAuxEntryLayout.MANIFESTS['Manifest'].splitlines()[1]
      + '\n'),
     (DisjointHashSetEntryLayout,
      'DATA test 0 MD5 9e107d9d372bb6826bd81d3542a419d6 '
      'SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n'),
     (MismatchedSizeLayout,
      MismatchedSizeLayout.MANIFESTS['Manifest'].splitlines()[1] + '\n'),
     (MismatchedChecksumLayout,
      MismatchedChecksumLayout.MANIFESTS['Manifest'].splitlines()[2] +
      '\n'),
     (CompressedTopManifestLayout,
      CompressedTopManifestLayout.MANIFESTS['Manifest.gz']),
     ])
def test_write_deduplicated_manifest(layout_factory, layout, expected):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    m.get_deduplicated_file_entry_dict_for_update()
    m.save_manifests()
    with open_potentially_compressed_path(tmp_path / layout.TOP_MANIFEST,
                                          'r') as f:
        contents = f.read()
    assert contents == expected


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
def test_new_manifest_without_create(layout_factory, filename):
    tmp_path = layout_factory.create(NewManifestLayout)
    with pytest.raises(FileNotFoundError):
        ManifestRecursiveLoader(tmp_path / filename)


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
def test_new_manifest_create_no_save(layout_factory, filename):
    tmp_path = layout_factory.create(NewManifestLayout)
    m = ManifestRecursiveLoader(tmp_path / filename,
                                allow_create=True)
    del m
    assert sorted(os.listdir(tmp_path)) == ['sub', 'test']


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
def test_new_manifest_create_save(layout_factory, filename):
    tmp_path = layout_factory.create(NewManifestLayout)
    m = ManifestRecursiveLoader(tmp_path / filename,
                                allow_create=True)
    m.save_manifests()
    assert sorted(os.listdir(tmp_path)) == [filename, 'sub', 'test']


@pytest.mark.parametrize(
    'filename,compress_watermark,expected',
    [('Manifest', None, 'Manifest'),
     ('Manifest', 0, 'Manifest'),
     ('Manifest.gz', None, 'Manifest.gz'),
     ('Manifest.gz', 0, 'Manifest.gz'),
     ('Manifest.gz', 4096, 'Manifest'),
     ])
def test_new_manifest_create_update(layout_factory,
                                    filename,
                                    compress_watermark,
                                    expected):
    tmp_path = layout_factory.create(NewManifestLayout)
    m = ManifestRecursiveLoader(tmp_path / filename,
                                allow_create=True,
                                hashes=['MD5'])
    m.update_entries_for_directory('')
    m.save_manifests(compress_watermark=compress_watermark)
    assert sorted(os.listdir(tmp_path)) == [expected, 'sub', 'test']
    m.assert_directory_verifies('')

    # implicit compression should not affect top Manifest
    with open_potentially_compressed_path(tmp_path / expected, 'r') as f:
        contents = f.read()
    expected = '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip()
    assert contents == expected


@pytest.mark.parametrize('args', ['', '--compress-watermark=0'])
def test_new_manifest_cli(layout_factory, args):
    tmp_path = layout_factory.create(NewManifestLayout)
    assert gemato.cli.main(['gemato', 'create', '--hashes=MD5'] +
                           args.split() + [str(tmp_path)]) == 0

    with open(tmp_path / 'Manifest') as f:
        contents = f.read()
    expected = '''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''.lstrip()
    assert contents == expected


@pytest.mark.parametrize(
    'layout,expected,expected_with_entry',
    [(NestedManifestLayout, ['a/Manifest', 'b/Manifest'],
      ['a/x/Manifest', 'a/z/Manifest']),
     (AddToMultiManifestLayout, ['a/Manifest'], []),
     ])
def test_load_unregistered_manifests(layout_factory,
                                     layout,
                                     expected,
                                     expected_with_entry):
    tmp_path = layout_factory.create(layout)
    # remove the top Manifest
    os.unlink(tmp_path / 'Manifest')
    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                allow_create=True)
    loaded = m.load_unregistered_manifests('')
    assert sorted(loaded) == sorted(expected + expected_with_entry)
    assert sorted(m.loaded_manifests) == sorted(['Manifest'] + loaded)
    assert list(m.updated_manifests) == ['Manifest']
    # new entries are not added to Manifest
    for path in expected:
        assert get_entry(m.find_path_entry(path)) is None


def test_regenerate_update_manifest(layout_factory):
    layout = NestedManifestLayout
    tmp_path = layout_factory.create(layout)
    # remove the top Manifest
    os.unlink(tmp_path / 'Manifest')
    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                allow_create=True)
    m.update_entries_for_directory('', hashes=['MD5'])
    m.save_manifests(sort=True)

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    expected = {
        'Manifest': 'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n'
        'MANIFEST a/Manifest 220 MD5 8e387c62a971e90f8cc1ea5e740647dd\n'
        'MANIFEST b/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n',
        'a/Manifest':
        'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n'
        'DATA y/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n'
        'MANIFEST x/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n'
        'MANIFEST z/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c\n',
        'a/x/Manifest':
        'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
        'a/z/Manifest':
        'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
        'b/Manifest':
        'DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e\n',
    }
    assert output == expected

    m.assert_directory_verifies()


def test_create_manifest(layout_factory):
    layout = NestedManifestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / 'Manifest')
    new_manifest = m.create_manifest('a/y/Manifest')
    assert new_manifest is not None
    assert not os.path.exists(tmp_path / 'a/y/Manifest')
    m.loaded_manifests['Manifest'].entries.append(
        gemato.manifest.ManifestEntryMANIFEST('a/y/Manifest', 0, {}))
    m.save_manifests()
    assert os.path.exists(tmp_path / 'a/y/Manifest')


def test_verify_mtime_old(layout_factory):
    layout = MismatchedFileLayout
    tmp_path = layout_factory.create(layout, readonly=True)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    with pytest.raises(ManifestMismatch):
        m.assert_directory_verifies('', last_mtime=0)


def test_verify_mtime_new(layout_factory):
    layout = MismatchedFileLayout
    tmp_path = layout_factory.create(layout, readonly=True)
    st = os.stat(tmp_path / 'test')
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False)
    m.assert_directory_verifies('', last_mtime=st.st_mtime)


class FILE_STAT:
    pass


@pytest.mark.parametrize(
    'last_mtime,manifest_update',
    [(0, {'Manifest':
          'DATA test 11 MD5 6f8db599de986fab7a21625b7916589c\n'}),
     (FILE_STAT, {}),
     ])
def test_update_mtime(layout_factory, last_mtime, manifest_update):
    layout = MismatchedFileLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=['MD5'],
                                allow_xdev=False)

    if last_mtime is FILE_STAT:
        st = os.stat(tmp_path / 'test')
        last_mtime = st.st_mtime
    m.update_entries_for_directory('', last_mtime=last_mtime)
    m.save_manifests()

    output = {}
    for relpath in layout.MANIFESTS:
        with open_potentially_compressed_path(tmp_path / relpath,
                                              'r') as f:
            output[relpath] = f.read()
    expected = dict(layout.MANIFESTS)
    expected.update(manifest_update)
    assert output == expected


INSECURE_HASH_TESTS = [
    # hashes, insecure
    ("MD5", ["MD5"]),
    ("SHA1", ["SHA1"]),
    ("SHA512", None),
    ("SHA1 SHA512", ["SHA1"]),
    ("", []),
]

INSECURE_HASH_VERIFY_TESTS = [
    # layout, insecure
    (UnknownHashLayout, ["MD5"]),
    (SecureHashLayout, None),
]


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
def test_insecure_hashes(layout_factory, hashes_arg, insecure):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    ctx = (pytest.raises(ManifestInsecureHashes) if insecure is not None
           else contextlib.nullcontext())
    with ctx:
        ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=hashes_arg.split(),
                                allow_xdev=False,
                                require_secure_hashes=True)


@pytest.mark.parametrize("layout,insecure", INSECURE_HASH_VERIFY_TESTS)
@pytest.mark.parametrize(
    "func,path",
    [(ManifestRecursiveLoader.verify_path, "test"),
     (ManifestRecursiveLoader.assert_path_verifies, "test"),
     (ManifestRecursiveLoader.assert_directory_verifies, ""),
     ])
def test_insecure_hashes_verify(layout_factory, layout, insecure, func, path):
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False,
                                require_secure_hashes=True)

    ctx = (pytest.raises(ManifestInsecureHashes) if insecure is not None
           else contextlib.nullcontext())
    with ctx:
        func(m, path)


def test_insecure_hashes_load(layout_factory):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False,
                                require_secure_hashes=True)

    with pytest.raises(ManifestInsecureHashes):
        m.load_manifests_for_path("sub")


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize(
    "func,arg",
    [(ManifestRecursiveLoader.update_entry_for_path, "sub/deeper/test"),
     (ManifestRecursiveLoader.update_entries_for_directory, "sub/deeper"),
     ])
def test_insecure_hashes_update(layout_factory, hashes_arg, insecure, func,
                                arg):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                hashes=["SHA512"],
                                allow_xdev=False,
                                require_secure_hashes=True)
    ctx = (pytest.raises(ManifestInsecureHashes) if insecure is not None
           else contextlib.nullcontext())
    with ctx:
        func(m, arg, hashes=hashes_arg.split())


def test_insecure_hashes_update_no_arg(layout_factory):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    m = ManifestRecursiveLoader(tmp_path / layout.TOP_MANIFEST,
                                allow_xdev=False,
                                require_secure_hashes=True)
    with pytest.raises(ManifestInsecureHashes):
        m.update_entry_for_path("sub/deeper/test")


@pytest.mark.parametrize("layout,insecure", INSECURE_HASH_VERIFY_TESTS)
def test_insecure_hashes_verify_cli(layout_factory, caplog, layout,
                                    insecure):
    tmp_path = layout_factory.create(layout)
    expected = 1 if insecure is not None else 0
    assert gemato.cli.main(["gemato", "verify", "--require-secure-hashes",
                            str(tmp_path)]) == expected
    if insecure is not None:
        assert str(ManifestInsecureHashes(insecure)) in caplog.text


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize("command", ["create", "update"])
def test_insecure_hashes_update_cli(layout_factory, caplog,
                                    hashes_arg, insecure, command):
    layout = BasicTestLayout
    tmp_path = layout_factory.create(layout)
    expected = 1 if insecure is not None else 0
    assert gemato.cli.main(["gemato", command, "--hashes", hashes_arg,
                            "--require-secure-hashes", "--force-rewrite",
                            str(tmp_path)]) == expected
    if insecure:
        assert str(ManifestInsecureHashes(insecure)) in caplog.text
