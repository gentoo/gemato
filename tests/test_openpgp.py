# gemato: OpenPGP signature support tests
# (c) 2017-2025 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

import contextlib
import datetime
import io
import logging
import os
import shlex
import signal
import subprocess
import tempfile

from functools import cache
from pathlib import Path

import pytest

import gemato.cli
from gemato.compression import open_potentially_compressed_path
from gemato.exceptions import (
    ManifestUnsignedData,
    ManifestSyntaxError,
    OpenPGPNoImplementation,
    OpenPGPVerificationFailure,
    OpenPGPExpiredKeyFailure,
    OpenPGPRevokedKeyFailure,
    OpenPGPKeyImportError,
    OpenPGPKeyListingError,
    OpenPGPKeyRefreshError,
    OpenPGPRuntimeError,
    OpenPGPUntrustedSigFailure,
    ManifestInsecureHashes,
    )
from gemato.manifest import ManifestFile
from gemato.openpgp import (
    GNUPG,
    SystemGPGEnvironment,
    IsolatedGPGEnvironment,
    PGPyEnvironment,
    get_wkd_url,
    OpenPGPSignatureList,
    OpenPGPSignatureData,
    OpenPGPSignatureStatus,
    )
from gemato.recursiveloader import ManifestRecursiveLoader

from tests.test_recursiveloader import INSECURE_HASH_TESTS
from tests.testutil import HKPServer


data_dir = Path(__file__).parent / "data"


def break_sig(sig):
    """Return signature packet mangled to mismatch the signed key"""
    return sig[:-1] + b'\x55'


def dash_escape(data: str) -> str:
    """Add dash escapes to Manifest"""
    return "".join(
        [
            f"- {x}\n"
            if x.startswith(("TIMESTAMP", "MANIFEST", "DATA", "DIST"))
            else f"{x}\n"
            for x in data.splitlines()
        ]
    )


def modify_manifest(data: str) -> str:
    """Return the "modified" Manifest variation"""
    return "".join(
        [
            x.split(" 0 ", 1)[0] + " 32\n"
            if x.startswith("DATA")
            else f"{x}\n"
            for x in data.splitlines()
        ]
    )


def _(path: str) -> bytes:
    return data_dir.joinpath(path).read_bytes()


def F(path: str) -> str:
    return data_dir.joinpath(path).read_text().strip()


def T(path: str) -> str:
    return data_dir.joinpath(path).read_text()


# == first key (used for most of the tests) ==
PUBLIC_KEY = _("first-key/pub")
SECRET_KEY = _("first-key/secret")
# (subkey optionally used)
PUBLIC_SUBKEY = _("first-key/subkey")
# main UID
UID = _("first-key/uid")
# UID without email
UID_NOEMAIL = _("first-key/uid-noemail")
# UID that's not valid UTF-8
UID_NONUTF = _("first-key/uid-nonutf")

# UID signatures without expiration date
PUBLIC_KEY_SIG = _("first-key/uid-sig")
PUBLIC_KEY_NOEMAIL_SIG = _("first-key/uid-noemail-sig")
PUBLIC_KEY_NONUTF_SIG = _("first-key/uid-nonutf-sig")
# subkey signature without expiration date
PUBLIC_SUBKEY_SIG = _("first-key/subkey-sig")
# main UID signature that expired
EXPIRED_KEY_SIG = _("first-key/expired-sig")
# main UID revocation signature
REVOCATION_SIG = _("first-key/revocation-sig")
# main UID signature without expiration that's newer than expired-sig
UNEXPIRE_SIG = _("first-key/unexpire-sig")

# == other key (used in WKD tests, has the same UID as first key) ==
OTHER_PUBLIC_KEY = _("other-key/pub")
OTHER_PUBLIC_KEY_UID = _("other-key/uid")
OTHER_PUBLIC_KEY_SIG = _("other-key/uid-sig")

# == second key (using different UID) ==
SECOND_PUBLIC_KEY = _("second-key/pub")
SECOND_SECRET_KEY = _("second-key/secret")
SECOND_UID = _("second-key/uid")
SECOND_KEY_SIG = _("second-key/uid-sig")

# == combined variants of first-key ==
VALID_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
EXPIRED_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG + EXPIRED_KEY_SIG
REVOKED_PUBLIC_KEY = PUBLIC_KEY + REVOCATION_SIG + UID + PUBLIC_KEY_SIG
# using the original signature to "unexpire" a key should fail
OLD_UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + UNEXPIRE_SIG

PRIVATE_KEY = SECRET_KEY + UID + PUBLIC_KEY_SIG

VALID_KEY_NOEMAIL = PUBLIC_KEY + UID_NOEMAIL + PUBLIC_KEY_NOEMAIL_SIG
VALID_KEY_NONUTF = PUBLIC_KEY + UID_NONUTF + PUBLIC_KEY_NONUTF_SIG

VALID_KEY_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                    PUBLIC_SUBKEY_SIG)

# first-key with broken signature
FORGED_PUBLIC_KEY = PUBLIC_KEY + UID + break_sig(PUBLIC_KEY_SIG)
FORGED_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                 break_sig(PUBLIC_SUBKEY_SIG))
FORGED_UNEXPIRE_KEY = (PUBLIC_KEY + UID + EXPIRED_KEY_SIG +
                       break_sig(UNEXPIRE_SIG))

# first-key without signatures
UNSIGNED_PUBLIC_KEY = PUBLIC_KEY + UID
UNSIGNED_SUBKEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY

# == key fingerprints ==
KEY_FINGERPRINT = F("first-key/fpr.txt")
SUBKEY_FINGERPRINT = F("first-key/sub-fpr.txt")
OTHER_KEY_FINGERPRINT = F("other-key/fpr.txt")
SECOND_KEY_FINGERPRINT = F("second-key/fpr.txt")

# == combined variants for other-key ==
OTHER_VALID_PUBLIC_KEY = (OTHER_PUBLIC_KEY + OTHER_PUBLIC_KEY_UID +
                          OTHER_PUBLIC_KEY_SIG)
COMBINED_PUBLIC_KEYS = OTHER_VALID_PUBLIC_KEY + VALID_PUBLIC_KEY

# == combined variants for second-key ==
SECOND_VALID_PUBLIC_KEY = SECOND_PUBLIC_KEY + SECOND_UID + SECOND_KEY_SIG
TWO_SIGNATURE_PUBLIC_KEYS = VALID_PUBLIC_KEY + SECOND_VALID_PUBLIC_KEY
TWO_KEYS_ONE_EXPIRED = EXPIRED_PUBLIC_KEY + SECOND_VALID_PUBLIC_KEY

# key with CRC error
MALFORMED_PUBLIC_KEY = _("malformed-key.txt")
# Manifest signed before first-key expired
SIGNED_MANIFEST = T("Manifest.asc")
# Manifest signed after first-key expired
POST_EXPIRATION_SIGNED_MANIFEST = T("Manifest.asc-post-expiration")
# valid Manifest with dash-escaped content
DASH_ESCAPED_SIGNED_MANIFEST = dash_escape(SIGNED_MANIFEST)
# Manifest with modified text (should fail)
MODIFIED_SIGNED_MANIFEST = modify_manifest(SIGNED_MANIFEST)
# Manifest with expired signature itself
EXPIRED_SIGNED_MANIFEST = T("Manifest.asc-expired")
# Manifest signed using the subkey
SUBKEY_SIGNED_MANIFEST = T("Manifest.asc-subkey-signed")
# combined signatures from first-key + second-key
TWO_SIGNATURE_MANIFEST = T("Manifest.asc-two-signatures")

# expected / base Manifest path (used for detached signature tests)
MANIFEST_PATH = data_dir / "Manifest"
# combined signatures from first-key + second-key
TWO_SIGNATURE_PATH = data_dir / "two-signatures.bin"


def strip_openpgp(text):
    lines = text.lstrip().splitlines()
    start = lines.index('')
    stop = lines.index('-----BEGIN PGP SIGNATURE-----')
    return '\n'.join(lines[start+1:stop-start+1]) + '\n'


@cache
def is_sequoia() -> bool:
    """Return True if GNUPG is sequoia-chameleon-gnupg"""
    try:
        out = subprocess.run([GNUPG, "--version"], capture_output=True)
    except OSError:
        return False
    return out.returncode == 0 and b"sequoia" in out.stdout


sequoia_xfail = pytest.mark.xfail(is_sequoia(),
                                  reason="FIXME on sequoia-chameleon-gnupg")


@pytest.mark.parametrize('manifest_var',
                         ["SIGNED_MANIFEST",
                          "DASH_ESCAPED_SIGNED_MANIFEST",
                          "SUBKEY_SIGNED_MANIFEST",
                          "MODIFIED_SIGNED_MANIFEST",
                          "EXPIRED_SIGNED_MANIFEST",
                          "TWO_SIGNATURE_MANIFEST",
                          "POST_EXPIRATION_SIGNED_MANIFEST",
                          ])
def test_noverify_goodish_manifest_load(manifest_var):
    """Test Manifest files that should succeed (OpenPGP disabled)"""
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        m.load(f, verify_openpgp=False)
    assert m.find_timestamp() is not None
    assert m.find_path_entry('myebuild-0.ebuild') is not None
    assert not m.openpgp_signed
    assert m.openpgp_signature is None


SIGNED_MANIFEST_JUNK_BEFORE = 'IGNORE test\n' + SIGNED_MANIFEST
SIGNED_MANIFEST_JUNK_AFTER = SIGNED_MANIFEST + 'IGNORE test\n'
SIGNED_MANIFEST_CUT_BEFORE_DATA = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:3])
SIGNED_MANIFEST_CUT_BEFORE_SIGNATURE = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:7])
SIGNED_MANIFEST_CUT_BEFORE_END = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:15])


@pytest.mark.parametrize('manifest_var,expected',
                         [('SIGNED_MANIFEST_JUNK_BEFORE',
                           ManifestUnsignedData),
                          ('SIGNED_MANIFEST_JUNK_AFTER',
                           ManifestUnsignedData),
                          ('SIGNED_MANIFEST_CUT_BEFORE_DATA',
                           ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_SIGNATURE',
                           ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_END',
                           ManifestSyntaxError),
                          ])
def test_noverify_bad_manifest_load(manifest_var, expected):
    """Test Manifest files that should fail"""
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        with pytest.raises(expected):
            m.load(f, verify_openpgp=False)


@pytest.mark.parametrize('write_back', [False, True])
def test_noverify_recursive_manifest_loader(tmp_path, write_back):
    """Test reading signed Manifest"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(MODIFIED_SIGNED_MANIFEST)

    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                verify_openpgp=False)
    assert not m.openpgp_signed
    assert m.openpgp_signature is None

    if write_back:
        m.save_manifest('Manifest')
        with open(tmp_path / 'Manifest') as f:
            assert f.read() == strip_openpgp(MODIFIED_SIGNED_MANIFEST)


def test_noverify_load_cli(tmp_path):
    """Test reading signed Manifest via CLI"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(MODIFIED_SIGNED_MANIFEST)
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass
    with open(tmp_path / 'myebuild-0.ebuild', 'wb') as f:
        f.write(b'12345678901234567890123456789012')
    with open(tmp_path / 'metadata.xml', 'wb'):
        pass

    assert 0 == gemato.cli.main(['gemato', 'verify',
                                 '--no-openpgp-verify', str(tmp_path)])


class MockedSystemGPGEnvironment(SystemGPGEnvironment):
    """System environment variant mocked to use isolated GNUPGHOME"""
    def __init__(self, *args, **kwargs):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._home = self._tmpdir.name
        os.environ['GNUPGHOME'] = self._tmpdir.name
        super().__init__(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        self.close()

    def close(self):
        if self._tmpdir is not None:
            IsolatedGPGEnvironment.close(self)
            # we need to recreate it to make cleanup() happy
            os.mkdir(self._tmpdir.name)
            self._tmpdir.cleanup()
            self._tmpdir = None
            os.environ.pop('GNUPGHOME', None)

    def import_key(self, keyfile, trust=True):
        IsolatedGPGEnvironment.import_key(self, keyfile, trust=trust)


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        MockedSystemGPGEnvironment,
                        PGPyEnvironment,
                        ])
def openpgp_env(request):
    """OpenPGP environment fixture"""
    try:
        env = request.param()
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    yield env
    env.close()


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        ])
def openpgp_env_with_refresh(request):
    """OpenPGP environments that support refreshing keys"""
    env = request.param()
    yield env
    env.close()


MANIFEST_VARIANTS = [
    # manifest, key, expected fpr/exception
    # == good manifests ==
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', None),
    ('SIGNED_MANIFEST', 'VALID_KEY_NONUTF', None),
    ('SIGNED_MANIFEST', 'COMBINED_PUBLIC_KEYS', None),
    ('DASH_ESCAPED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_KEY_SUBKEY', None),
    ("POST_EXPIRATION_SIGNED_MANIFEST", "VALID_PUBLIC_KEY", None),
    # == Manifest signed before the key expired ==
    ("SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", None),
    # == Manifest with two signatures ==
    ("TWO_SIGNATURE_MANIFEST", "TWO_SIGNATURE_PUBLIC_KEYS", None),
    ("TWO_SIGNATURE_MANIFEST", "VALID_PUBLIC_KEY", OpenPGPVerificationFailure),
    ("TWO_SIGNATURE_MANIFEST", "SECOND_VALID_PUBLIC_KEY",
     OpenPGPVerificationFailure),
    ("TWO_SIGNATURE_MANIFEST", "TWO_KEYS_ONE_EXPIRED",
     OpenPGPExpiredKeyFailure),
    # == using private key ==
    ('SIGNED_MANIFEST', 'PRIVATE_KEY', None),
    # == bad manifests ==
    ('MODIFIED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    ('EXPIRED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    # == bad keys ==
    ('SIGNED_MANIFEST', None,
     OpenPGPVerificationFailure),
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY",
     OpenPGPExpiredKeyFailure),
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY',
     OpenPGPRevokedKeyFailure),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    ('SIGNED_MANIFEST', 'UNSIGNED_PUBLIC_KEY',
     OpenPGPKeyImportError),
    ('SIGNED_MANIFEST', 'FORGED_PUBLIC_KEY',
     OpenPGPKeyImportError),
    ('SUBKEY_SIGNED_MANIFEST', 'UNSIGNED_SUBKEY',
     OpenPGPVerificationFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'FORGED_SUBKEY',
     OpenPGPVerificationFailure),
]


def assert_signature(sig: OpenPGPSignatureList,
                     manifest_var: str,
                     expect_both: bool = True,
                     ) -> None:
    """Make assertions about the signature"""
    if manifest_var == "TWO_SIGNATURE_MANIFEST":
        no_key_sig = OpenPGPSignatureData(
            sig_status=OpenPGPSignatureStatus.NO_PUBLIC_KEY)
        assert sorted(sig) == sorted([
            OpenPGPSignatureData(
                fingerprint=KEY_FINGERPRINT,
                timestamp=datetime.datetime(2024, 1, 1),
                primary_key_fingerprint=KEY_FINGERPRINT,
                sig_status=OpenPGPSignatureStatus.GOOD,
                trusted_sig=True,
                valid_sig=True,
                ),
            OpenPGPSignatureData(
                fingerprint=SECOND_KEY_FINGERPRINT,
                timestamp=datetime.datetime(2020, 1, 1),
                primary_key_fingerprint=SECOND_KEY_FINGERPRINT,
                sig_status=OpenPGPSignatureStatus.GOOD,
                trusted_sig=True,
                valid_sig=True,
                ) if expect_both else no_key_sig,
        ])
    elif manifest_var == 'SUBKEY_SIGNED_MANIFEST':
        assert len(sig) == 1
        assert sig.fingerprint == SUBKEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2020, 1, 1)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT
    elif manifest_var == "POST_EXPIRATION_SIGNED_MANIFEST":
        assert len(sig) == 1
        assert sig.fingerprint == KEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2024, 1, 1)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT
    else:
        assert len(sig) == 1
        assert sig.fingerprint == KEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2020, 1, 1)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_verify_manifest(openpgp_env, manifest_var, key_var, expected):
    """Test direct Manifest data verification"""
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as kf:
                        openpgp_env.import_key(kf)

                sig = openpgp_env.verify_file(f)
                assert_signature(sig, manifest_var)
            else:
                with pytest.raises(expected):
                    if key_var is not None:
                        with io.BytesIO(globals()[key_var]) as kf:
                            openpgp_env.import_key(kf)

                    openpgp_env.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_verify_one_out_of_two():
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env.import_key(f)

            with io.StringIO(TWO_SIGNATURE_MANIFEST) as f:
                sig = openpgp_env.verify_file(f, require_all_good=False)

            assert_signature(sig, "TWO_SIGNATURE_MANIFEST", expect_both=False)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_verify_untrusted_key():
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env.import_key(f, trust=False)

            with io.StringIO(SIGNED_MANIFEST) as f:
                with pytest.raises(OpenPGPUntrustedSigFailure):
                    openpgp_env.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_manifest_load(openpgp_env, manifest_var, key_var, expected):
    """Test Manifest verification via ManifestFile.load()"""
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        key_loaded = False
        m = ManifestFile()
        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as kf:
                        openpgp_env.import_key(kf)

                key_loaded = True
                m.load(f, openpgp_env=openpgp_env)
                assert m.openpgp_signed
                assert_signature(m.openpgp_signature, manifest_var)
            else:
                with pytest.raises(expected):
                    if key_var is not None:
                        with io.BytesIO(globals()[key_var]) as kf:
                            openpgp_env.import_key(kf)

                    key_loaded = True
                    m.load(f, openpgp_env=openpgp_env)
                assert not m.openpgp_signed
                assert m.openpgp_signature is None

        if key_loaded:
            # Manifest entries should be loaded even if verification failed
            assert m.find_timestamp() is not None
            assert m.find_path_entry('myebuild-0.ebuild') is not None
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_recursive_manifest_loader(tmp_path, openpgp_env, filename,
                                   manifest_var, key_var, expected):
    """Test Manifest verification via ManifestRecursiveLoader"""
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        with open_potentially_compressed_path(tmp_path / filename, 'w') as cf:
            cf.write(globals()[manifest_var])

        if expected is None:
            if key_var is not None:
                with io.BytesIO(globals()[key_var]) as f:
                    openpgp_env.import_key(f)

            m = ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
            assert m.openpgp_signed
            assert_signature(m.openpgp_signature, manifest_var)
        else:
            with pytest.raises(expected):
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as f:
                        openpgp_env.import_key(f)

                ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.fixture
def base_tree(tmp_path):
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass
    with open(tmp_path / 'myebuild-0.ebuild', 'wb'):
        pass
    with open(tmp_path / 'metadata.xml', 'wb'):
        pass
    return tmp_path


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         [(m, k, e) for m, k, e in MANIFEST_VARIANTS
                          if k is not None])
def test_cli(base_tree, caplog, manifest_var, key_var, expected):
    """Test Manifest verification via CLI"""
    with open(base_tree / '.key.bin', 'wb') as f:
        f.write(globals()[key_var])
    with open(base_tree / 'Manifest', 'w') as f:
        f.write(globals()[manifest_var])
    if manifest_var == 'MODIFIED_SIGNED_MANIFEST':
        with open(base_tree / 'myebuild-0.ebuild', 'wb') as f:
            f.write(b'12345678901234567890123456789012')

    retval = gemato.cli.main(['gemato', 'verify',
                              '--openpgp-key',
                              str(base_tree / '.key.bin'),
                              '--no-refresh-keys',
                              '--require-signed-manifest',
                              # we verify this option separately
                              # and our test data currently sucks
                              '--no-require-secure-hashes',
                              str(base_tree)])
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    eexit = 0 if expected is None else 1
    assert retval == eexit
    if expected is not None:
        assert str(expected('')) in caplog.text


EMPTY_DATA = b''


@pytest.mark.parametrize(
    'key_var,success',
    [('VALID_PUBLIC_KEY', True),
     ('VALID_KEY_NOEMAIL', True),
     ('VALID_KEY_NONUTF', True),
     ('MALFORMED_PUBLIC_KEY', False),
     ('EMPTY_DATA', False),
     ('FORGED_PUBLIC_KEY', False),
     ('UNSIGNED_PUBLIC_KEY', False),
     ])
def test_env_import_key(openpgp_env, key_var, success):
    """Test importing valid and invalid keys"""
    try:
        if success:
            openpgp_env.import_key(io.BytesIO(globals()[key_var]))
        else:
            with pytest.raises(OpenPGPKeyImportError):
                openpgp_env.import_key(io.BytesIO(globals()[key_var]))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_env_double_close():
    """Test that env can be closed multiple times"""
    with IsolatedGPGEnvironment() as env:
        env.close()


def test_env_home_after_close():
    """Test that .home can not be referenced after closing"""
    with IsolatedGPGEnvironment() as env:
        env.close()
        with pytest.raises(AssertionError):
            env.home


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        MockedSystemGPGEnvironment,
                        ])
def privkey_env(request):
    """Environment with private key loaded"""
    try:
        env = request.param()
        env.import_key(io.BytesIO(PRIVATE_KEY))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    yield env
    env.close()


TEST_STRING = 'The quick brown fox jumps over the lazy dog'


@sequoia_xfail
@pytest.mark.parametrize('keyid', [None, KEY_FINGERPRINT])
def test_sign_data(privkey_env, keyid):
    """Test signing data"""
    with io.StringIO(TEST_STRING) as f:
        with io.StringIO() as wf:
            privkey_env.clear_sign_file(f, wf, keyid=keyid)
            wf.seek(0)
            privkey_env.verify_file(wf)


@pytest.mark.parametrize('keyid', [None, KEY_FINGERPRINT])
@pytest.mark.parametrize('sign', [None, False, True])
def test_dump_signed_manifest(privkey_env, keyid, sign):
    """Test dumping a signed Manifest"""
    if sign is not False and is_sequoia():
        pytest.xfail("FIXME: sequoia-chameleon-gnupg fails to sign")

    m = ManifestFile()
    verify = True if sign is None else False
    with io.StringIO(SIGNED_MANIFEST) as f:
        m.load(f, verify_openpgp=verify, openpgp_env=privkey_env)
    assert m.openpgp_signed == verify

    with io.StringIO() as f:
        m.dump(f, openpgp_keyid=keyid, openpgp_env=privkey_env,
               sign_openpgp=sign)
        f.seek(0)
        m.load(f, openpgp_env=privkey_env)
    if sign is not False:
        assert m.openpgp_signed
        assert m.openpgp_signature is not None
    else:
        assert not m.openpgp_signed
        assert m.openpgp_signature is None


@sequoia_xfail
@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
@pytest.mark.parametrize('sign', [None, True])
def test_recursive_manifest_loader_save_manifest(tmp_path, privkey_env,
                                                 filename, sign):
    """Test signing Manifests via ManifestRecursiveLoader"""
    with open_potentially_compressed_path(tmp_path / filename, 'w') as cf:
        cf.write(SIGNED_MANIFEST)

    verify = not sign
    m = ManifestRecursiveLoader(tmp_path / filename,
                                verify_openpgp=verify,
                                sign_openpgp=sign,
                                openpgp_env=privkey_env)
    assert m.openpgp_signed == verify

    m.save_manifest(filename)
    m2 = ManifestFile()
    with open_potentially_compressed_path(tmp_path / filename, 'r') as cf:
        m2.load(cf, openpgp_env=privkey_env)
    assert m2.openpgp_signed
    assert m2.openpgp_signature is not None


def test_recursive_manifest_loader_save_submanifest(tmp_path, privkey_env):
    """Test that sub-Manifests are not signed"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(SIGNED_MANIFEST)
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass

    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                verify_openpgp=False,
                                sign_openpgp=True,
                                openpgp_env=privkey_env)
    assert not m.openpgp_signed
    assert m.openpgp_signature is None

    m.load_manifest('eclass/Manifest')
    m.save_manifest('eclass/Manifest')

    m2 = ManifestFile()
    with open(tmp_path / 'eclass' / 'Manifest') as f:
        m2.load(f, openpgp_env=privkey_env)
    assert not m2.openpgp_signed
    assert m2.openpgp_signature is None


@pytest.mark.parametrize(
    'key_var,expected',
    [('VALID_PUBLIC_KEY',
      {KEY_FINGERPRINT: [b"gemato test key <gemato@example.com>"]}),
     ('OTHER_VALID_PUBLIC_KEY',
      {OTHER_KEY_FINGERPRINT: [b"gemato test key <gemato@example.com>"]}),
     ('VALID_KEY_SUBKEY',
      {KEY_FINGERPRINT: [b"gemato test key <gemato@example.com>"]}),
     ('VALID_KEY_NOEMAIL',
      {KEY_FINGERPRINT: [b"gemato test key"]}),
     ('VALID_KEY_NONUTF',
      {KEY_FINGERPRINT: [
           b"gemat\\xf6 test key <gemato@example.com>" if is_sequoia()
           else b"gemat\xf6 test key <gemato@example.com>"
       ]}),
     ])
def test_list_keys(openpgp_env, key_var, expected):
    try:
        openpgp_env.import_key(io.BytesIO(globals()[key_var]))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    assert openpgp_env.list_keys() == expected
    assert openpgp_env.list_keys(list(expected.keys())) == expected


def test_list_keys_empty(openpgp_env):
    try:
        assert openpgp_env.list_keys() == {}
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_list_keys_error(openpgp_env):
    try:
        with pytest.raises(OpenPGPKeyListingError):
            openpgp_env.list_keys(["zzzzz"])
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.fixture(scope='module')
def global_hkp_server():
    """A fixture that starts a single HKP server instance for tests"""
    server = HKPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def hkp_server(global_hkp_server):
    """A fixture that resets the global HKP server with empty keys"""
    global_hkp_server.keys.clear()
    yield global_hkp_server


REFRESH_VARIANTS = [
    # manifest, key, server key fpr, server key, expected exception
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_KEY_NONUTF', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'REVOKED_PUBLIC_KEY', OpenPGPRevokedKeyFailure),
    # test fetching subkey for primary key
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_KEY_SUBKEY', None),
    # refresh should fail if key is not on server
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None, None,
     OpenPGPKeyRefreshError),
    # unrevocation should not be possible
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', OpenPGPRevokedKeyFailure),
    # unexpiration should be possible
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'UNEXPIRE_PUBLIC_KEY', None),
    # ...but only with a new signature
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", KEY_FINGERPRINT,
     "OLD_UNEXPIRE_PUBLIC_KEY", OpenPGPExpiredKeyFailure),
    # make sure server can't malicously inject or replace key
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', OpenPGPKeyRefreshError),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'COMBINED_PUBLIC_KEYS', OpenPGPRuntimeError),
    # test that forged keys are rejected
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", KEY_FINGERPRINT,
     "FORGED_UNEXPIRE_KEY", OpenPGPExpiredKeyFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'FORGED_SUBKEY', OpenPGPVerificationFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'UNSIGNED_SUBKEY', OpenPGPVerificationFailure),
]


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected',
    REFRESH_VARIANTS +
    [('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', KEY_FINGERPRINT,
      'VALID_PUBLIC_KEY', None),
     ])
def test_refresh_hkp(openpgp_env_with_refresh, hkp_server, manifest_var,
                     key_var, server_key_fpr, server_key_var, expected):
    """Test refreshing against a HKP keyserver"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env_with_refresh.import_key(f)

        if server_key_var is not None:
            hkp_server.keys[server_key_fpr] = globals()[server_key_var]

        if expected is None:
            openpgp_env_with_refresh.refresh_keys(
                allow_wkd=False, keyserver=hkp_server.addr)
            with io.StringIO(globals()[manifest_var]) as f:
                openpgp_env_with_refresh.verify_file(f)
        else:
            with pytest.raises(expected):
                openpgp_env_with_refresh.refresh_keys(
                    allow_wkd=False, keyserver=hkp_server.addr)
                with io.StringIO(globals()[manifest_var]) as f:
                    openpgp_env_with_refresh.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected,'
    'expect_hit',
    [args + (True,) for args in REFRESH_VARIANTS] +
    [('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', KEY_FINGERPRINT,
      'VALID_PUBLIC_KEY', OpenPGPKeyRefreshError, False),
     ])
def test_refresh_wkd(openpgp_env_with_refresh,
                     manifest_var,
                     key_var,
                     server_key_fpr,
                     server_key_var,
                     expected,
                     expect_hit):
    """Test refreshing against WKD"""
    with pytest.importorskip('responses').RequestsMock(
            assert_all_requests_are_fired=expect_hit) as responses:
        try:
            if key_var is not None:
                with io.BytesIO(globals()[key_var]) as f:
                    openpgp_env_with_refresh.import_key(f)

            if server_key_var is not None:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    body=globals()[server_key_var],
                    content_type='application/pgp-keys')
            else:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    status=404)

            if expected is None:
                openpgp_env_with_refresh.refresh_keys(
                    allow_wkd=True, keyserver='hkps://block.invalid/')
                with io.StringIO(globals()[manifest_var]) as f:
                    openpgp_env_with_refresh.verify_file(f)
            else:
                with pytest.raises(expected):
                    openpgp_env_with_refresh.refresh_keys(
                        allow_wkd=True, keyserver='hkps://block.invalid/')
                    with io.StringIO(globals()[manifest_var]) as f:
                        openpgp_env_with_refresh.verify_file(f)
        except OpenPGPNoImplementation as e:
            pytest.skip(str(e))


@pytest.mark.parametrize('status', [401, 404, 500, ConnectionError])
def test_refresh_wkd_fallback_to_hkp(openpgp_env_with_refresh,
                                     hkp_server, caplog, status):
    """Test whether WKD refresh failure falls back to HKP"""
    with pytest.importorskip('responses').RequestsMock() as responses:
        try:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env_with_refresh.import_key(f)
            hkp_server.keys[KEY_FINGERPRINT] = REVOKED_PUBLIC_KEY
            if status is not ConnectionError:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    status=status)

            caplog.set_level(logging.DEBUG)
            openpgp_env_with_refresh.refresh_keys(
                allow_wkd=True, keyserver=hkp_server.addr)
            assert 'failing due to failed request' in caplog.text

            with pytest.raises(OpenPGPRevokedKeyFailure):
                with io.StringIO(SIGNED_MANIFEST) as f:
                    openpgp_env_with_refresh.verify_file(f)
        except OpenPGPNoImplementation as e:
            pytest.skip(str(e))


@pytest.mark.parametrize(
    'email,expected',
    [('gemato@example.com',
      'https://example.com/.well-known/openpgpkey/hu/'
      '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato'),
     ('Joe.Doe@Example.ORG',
      'https://example.org/.well-known/openpgpkey/hu/'
      'iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe'),
     ])
def test_get_wkd_url(email, expected):
    assert get_wkd_url(email) == expected


def signal_desc(sig):
    if hasattr(signal, 'strsignal'):
        return signal.strsignal(sig)
    else:
        return sig


@pytest.mark.parametrize(
    'command,expected,match',
    [('true', 0, None),
     ('false', 1, None),
     ('{gpg} --verify {tmp_path}/Manifest', 0, None),
     ('{gpg} --verify {tmp_path}/Manifest.subkey', 2, None),
     ('sh -c "kill $$"', -signal.SIGTERM,
      f'Child process terminated due to signal: '
      f'{signal_desc(signal.SIGTERM)}'),
     ('sh -c "kill -USR1 $$"', -signal.SIGUSR1,
      f'Child process terminated due to signal: '
      f'{signal_desc(signal.SIGUSR1)}'),
     ])
def test_cli_gpg_wrap(tmp_path, caplog, command, expected, match):
    with open(tmp_path / '.key.bin', 'wb') as f:
        f.write(VALID_PUBLIC_KEY)
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(SIGNED_MANIFEST)
    with open(tmp_path / 'Manifest.subkey', 'w') as f:
        f.write(SUBKEY_SIGNED_MANIFEST)

    command = [x.replace('{tmp_path}', str(tmp_path)).replace('{gpg}', GNUPG)
               for x in shlex.split(command)]
    retval = gemato.cli.main(['gemato', 'gpg-wrap',
                              '--openpgp-key',
                              str(tmp_path / '.key.bin'),
                              '--no-refresh-keys',
                              '--'] + command)
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    assert retval == expected
    if match is not None:
        assert match in caplog.text


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize(
    "sign,require_secure",
    [(None, None),
     (False, None),
     (True, None),
     (None, False),
     (True, False),
     ])
def test_recursive_manifest_loader_require_secure(tmp_path, privkey_env,
                                                  hashes_arg, insecure,
                                                  sign, require_secure):
    with open(tmp_path / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    ctx = (pytest.raises(ManifestInsecureHashes)
           if insecure is not None and sign is not False
           and require_secure is not False
           else contextlib.nullcontext())
    with ctx:
        m = ManifestRecursiveLoader(tmp_path / "Manifest",
                                    hashes=hashes_arg.split(),
                                    require_secure_hashes=require_secure,
                                    verify_openpgp=not sign,
                                    sign_openpgp=sign,
                                    openpgp_env=privkey_env)
        if not sign:
            assert m.openpgp_signed


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize(
    "sign,require_secure",
    [("", ""),
     ("--no-sign", ""),
     ("--sign", ""),
     ("", "--no-require-secure-hashes"),
     ("--sign", "--no-require-secure-hashes"),
     ])
def test_update_require_secure_cli(base_tree, caplog, hashes_arg,
                                   insecure, sign, require_secure):
    expected = (1 if insecure is not None and sign != "--no-sign"
                and require_secure != "--no-require-secure-hashes"
                else 0)
    if expected == 0 and is_sequoia():
        pytest.xfail("FIXME: sequoia-chameleon-gnupg fails to sign")

    with open(base_tree / ".key.bin", "wb") as keyf:
        keyf.write(PRIVATE_KEY)
    with open(base_tree / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    retval = gemato.cli.main(["gemato", "update",
                              "-K", str(base_tree / ".key.bin"),
                              "--hashes", hashes_arg,
                              str(base_tree)]
                             + f"{sign} {require_secure}".split())
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    assert retval == expected
    if expected == 1:
        assert str(ManifestInsecureHashes(insecure)) in caplog.text


@pytest.mark.parametrize(
    "require_secure", ["", "--no-require-secure-hashes"])
def test_verify_require_secure_cli(base_tree, caplog, require_secure):
    with open(base_tree / ".key.bin", "wb") as keyf:
        keyf.write(VALID_PUBLIC_KEY)
    with open(base_tree / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    retval = gemato.cli.main(["gemato", "verify",
                              "--no-refresh-keys",
                              "--require-signed-manifest",
                              "-K", str(base_tree / ".key.bin"),
                              str(base_tree)]
                             + require_secure.split())
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    expected = (1 if require_secure != "--no-require-secure-hashes"
                else 0)
    assert retval == expected
    if expected == 1:
        assert str(ManifestInsecureHashes(["MD5"])) in caplog.text


@pytest.mark.parametrize(
    "key_var,two_sigs",
    [("TWO_SIGNATURE_PUBLIC_KEYS", True),
     ("VALID_PUBLIC_KEY", False),
     ])
def test_verify_detached(tmp_path, key_var, two_sigs):
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

            with open(MANIFEST_PATH, "rb") as f:
                sig = openpgp_env.verify_detached(
                    TWO_SIGNATURE_PATH, f,
                    require_all_good=two_sigs)

            assert_signature(sig, "TWO_SIGNATURE_MANIFEST",
                             expect_both=two_sigs)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
