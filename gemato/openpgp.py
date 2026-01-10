# gemato: OpenPGP verification support
# (c) 2017-2024 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import base64
import dataclasses
import datetime
import email.utils
import enum
import errno
import hashlib
import logging
import math
import os
import os.path
import shutil
import subprocess
import tempfile
import typing
import urllib.parse
import warnings

from pathlib import Path

from gemato.exceptions import (
    OpenPGPNoImplementation,
    OpenPGPVerificationFailure,
    OpenPGPExpiredKeyFailure,
    OpenPGPRevokedKeyFailure,
    OpenPGPKeyImportError,
    OpenPGPKeyListingError,
    OpenPGPKeyRefreshError,
    OpenPGPUnknownSigFailure,
    OpenPGPUntrustedSigFailure,
    OpenPGPSigningFailure,
    )

try:
    import requests
except ImportError:
    requests = None

try:
    import pgpy
except ImportError:
    pgpy = None


GNUPG = os.environ.get('GNUPG', 'gpg')
GNUPGCONF = os.environ.get('GNUPGCONF', 'gpgconf')

LOGGER = logging.getLogger(__name__)


class OpenPGPSignatureStatus(enum.Enum):
    GOOD = enum.auto()
    BAD = enum.auto()
    EXPIRED = enum.auto()
    NO_PUBLIC_KEY = enum.auto()
    ERROR = enum.auto()
    EXPIRED_KEY = enum.auto()
    REVOKED_KEY = enum.auto()


@dataclasses.dataclass(order=True)
class OpenPGPSignatureData:
    fingerprint: str = ""
    timestamp: typing.Optional[datetime.datetime] = None
    expire_timestamp: typing.Optional[datetime.datetime] = None
    primary_key_fingerprint: str = ""
    sig_status: typing.Optional[OpenPGPSignatureStatus] = None
    valid_sig: bool = False
    trusted_sig: bool = False
    key_expiration: typing.Optional[datetime.datetime] = None


class OpenPGPSignatureList(list[OpenPGPSignatureData]):
    # backwards compatibility with OpenPGPSignatureData

    @property
    def fingerprint(self) -> str:
        return self[0].fingerprint

    @property
    def timestamp(self) -> typing.Optional[datetime.datetime]:
        return self[0].timestamp

    @property
    def expire_timestamp(self) -> typing.Optional[datetime.datetime]:
        return self[0].expire_timestamp

    @property
    def primary_key_fingerprint(self) -> str:
        return self[0].primary_key_fingerprint


ZBASE32_TRANSLATE = bytes.maketrans(
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    b'ybndrfg8ejkmcpqxot1uwisza345h769')


def get_wkd_url(email):
    localname, domain = email.split('@', 1)
    b32 = (
        base64.b32encode(
            hashlib.sha1(localname.encode('utf8').lower()).digest())
        .translate(ZBASE32_TRANSLATE).decode('ASCII'))
    return (f'https://{domain.lower()}/.well-known/openpgpkey/hu/'
            f'{b32}?l={urllib.parse.quote(localname)}')


class SystemGPGEnvironment:
    """
    OpenPGP environment class that uses the global OpenPGP environment
    (user's home directory or GNUPGHOME).
    """

    def __init__(self, debug=False, proxy=None, timeout=None):
        self.debug = debug
        self._trusted_keys = set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        pass

    def close(self):
        pass

    def import_key(self, keyfile, trust=True):
        """
        Import a public key from open file @keyfile. The file should
        be open for reading in binary mode, and oriented
        at the beginning.
        """

        raise NotImplementedError(
            'import_key() is not implemented by this OpenPGP provider')

    def list_keys(self, key_ids: list[str] = []
                  ) -> dict[str, list[tuple[str, str]]]:
        """
        List fingerprints and UIDs of specified keys or all keys in keyring

        Returns a mapping from fingerprint (as a string) to an iterable
        of UIDs.
        """

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--with-colons', '--list-keys', *key_ids],
            raise_on_error=OpenPGPKeyListingError)

        prev_pub = None
        fpr = None
        ret = {}
        for line in out.splitlines():
            if line.startswith(b"fpr:"):
                fpr = line.split(b":")[9].decode("ASCII")
                # this can be subkey fingerprint
                if prev_pub is None:
                    continue
                if not fpr.endswith(prev_pub):
                    raise OpenPGPKeyListingError(
                        f"Incorrect fingerprint {fpr} for key {prev_pub}"
                    )
                LOGGER.debug(
                    f"list_keys(): fingerprint: {fpr}")
                ret[fpr] = []
                prev_pub = None
            elif line.startswith(b"pub:"):
                if prev_pub is not None:
                    raise OpenPGPKeyListingError(
                        f"New key while waiting for fingerprint: {line} "
                        f"({prev_pub=})"
                    )
                # wait for the fingerprint
                prev_pub = line.split(b":")[4].decode("ASCII")
                LOGGER.debug(f"list_keys(): keyid: {prev_pub}")
            elif line.startswith(b"sub:"):
                if fpr is None:
                    raise OpenPGPKeyListingError(
                        "Subkey without prior fingerprint in GPG output: "
                        f"{line} ({prev_pub=})"
                    )
                prev_pub = None
            elif line.startswith(b'uid:'):
                if fpr is None:
                    raise OpenPGPKeyListingError(
                        f"UID without prior fingerprint in GPG output: {line} "
                        f"({prev_pub=})"
                    )
                uid_split = line.split(b":", 10)
                uid = uid_split[9]
                # no creation date means missing/broken self-sig
                if not uid_split[5]:
                    LOGGER.debug(
                        f"list_keys(): skipping UID with missing self-sig: "
                        f"{fpr=}, {uid=!r}")
                    continue
                LOGGER.debug(f'list_keys(): UID: {uid}')
                ret[fpr].append(uid)

        return ret

    def refresh_keys(self, allow_wkd=True, keyserver=None):
        """
        Update the keys from their assigned keyservers. This should be called
        at start of every execution in order to ensure that revocations
        are respected. This action requires network access.

        @allow_wkd specifies whether WKD can be used to fetch keys. This is
        experimental but usually is more reliable than keyservers.  If WKD
        fails to fetch *all* keys, gemato falls back to keyservers.

        @keyserver may be used to force an alternate keyserver. If its present,
        it should specify a keyserver URL.
        """

        raise NotImplementedError(
            'refresh_keys() is not implemented by this OpenPGP provider')

    def _parse_gpg_ts(self, ts):
        """
        Parse GnuPG status timestamp that can either be time_t value
        or ISO 8601 timestamp.
        """
        # that's how upstream tells us to detect this
        if 'T' in ts:
            # TODO: is this correct for all cases? is it localtime?
            return datetime.datetime.strptime(ts, '%Y%m%dT%H%M%S')
        elif ts == '0':
            # no timestamp
            return None
        else:
            return datetime.datetime.utcfromtimestamp(int(ts))

    def _process_gpg_verify_output(self,
                                   out: bytes,
                                   err: bytes,
                                   require_all_good: bool,
                                   ) -> OpenPGPSignatureList:
        """Process the output of gpg --verify and return a siglist"""

        sig_list = OpenPGPSignatureList()
        for line in out.splitlines():
            if line.startswith(b'[GNUPG:] NEWSIG'):
                sig_list.append(OpenPGPSignatureData())
            elif line.startswith(b'[GNUPG:] GOODSIG'):
                assert sig_list and sig_list[-1].sig_status is None
                sig_list[-1].sig_status = OpenPGPSignatureStatus.GOOD
            elif line.startswith(b"[GNUPG:] BADSIG"):
                assert sig_list and sig_list[-1].sig_status is None
                sig_list[-1].sig_status = OpenPGPSignatureStatus.BAD
            elif line.startswith(b"[GNUPG:] EXPSIG"):
                assert sig_list and sig_list[-1].sig_status is None
                sig_list[-1].sig_status = OpenPGPSignatureStatus.EXPIRED
            elif line.startswith(b"[GNUPG:] ERRSIG"):
                assert sig_list and sig_list[-1].sig_status is None
                spl = line.split(b" ")
                assert len(spl) >= 8
                if spl[7] == b"9":
                    sig_list[-1].sig_status = (
                        OpenPGPSignatureStatus.NO_PUBLIC_KEY)
                else:
                    sig_list[-1].sig_status = OpenPGPSignatureStatus.ERROR
            elif line.startswith(b'[GNUPG:] EXPKEYSIG'):
                assert sig_list and sig_list[-1].sig_status is None
                sig_list[-1].sig_status = OpenPGPSignatureStatus.EXPIRED_KEY
            elif line.startswith(b'[GNUPG:] REVKEYSIG'):
                assert sig_list and sig_list[-1].sig_status is None
                sig_list[-1].sig_status = OpenPGPSignatureStatus.REVOKED_KEY
            elif line.startswith(b'[GNUPG:] VALIDSIG'):
                assert sig_list and not sig_list[-1].valid_sig
                spl = line.split(b' ')
                assert len(spl) >= 12
                sig_list[-1].valid_sig = True
                sig_list[-1].fingerprint = spl[2].decode('utf8')
                sig_list[-1].timestamp = (
                    self._parse_gpg_ts(spl[4].decode('utf8')))
                sig_list[-1].expire_timestamp = (
                    self._parse_gpg_ts(spl[5].decode('utf8')))
                sig_list[-1].primary_key_fingerprint = spl[11].decode('utf8')
            elif line.startswith(b'[GNUPG:] TRUST_'):
                assert sig_list
                spl = line.split(b' ', 2)
                if spl[1] in (b'TRUST_MARGINAL',
                              b'TRUST_FULL',
                              b'TRUST_ULTIMATE'):
                    sig_list[-1].trusted_sig = True
            elif line.startswith(b"[GNUPG:] KEYEXPIRED"):
                # TODO: will the "correct" key be emitted last?
                assert sig_list
                spl = line.split(b" ", 3)
                assert len(spl) >= 3
                sig_list[-1].key_expiration = (
                    self._parse_gpg_ts(spl[2].decode("utf8")))

        if not sig_list:
            raise OpenPGPUnknownSigFailure(
                err.decode('utf8', errors='backslashreplace'))

        for sig in sig_list:
            # bad signature causes failure even without require_all_good
            if sig.sig_status == OpenPGPSignatureStatus.BAD:
                raise OpenPGPVerificationFailure(
                    err.decode("utf8", errors="backslashreplace"), sig)

            if sig.sig_status == OpenPGPSignatureStatus.EXPIRED_KEY:
                # if the signature was done using a key that's expired *now*,
                # check whether it was expired prior to the signature.
                assert sig.timestamp is not None
                assert sig.key_expiration is not None
                if sig.timestamp < sig.key_expiration:
                    sig.sig_status = OpenPGPSignatureStatus.GOOD
                    # we need to check the trust explicitly since GPG
                    # doesn't check trust on expired keys
                    if sig.primary_key_fingerprint in self._trusted_keys:
                        sig.trusted_sig = True
            else:
                # remove key_expiration if it the signature was not done
                # by an expired key
                sig.key_expiration = None

        if not require_all_good:
            if any(x.sig_status == OpenPGPSignatureStatus.GOOD and
                   x.valid_sig and x.trusted_sig for x in sig_list):
                return sig_list

        for sig in sig_list:
            if sig.sig_status == OpenPGPSignatureStatus.GOOD:
                pass
            elif sig.sig_status in (OpenPGPSignatureStatus.BAD,
                                    OpenPGPSignatureStatus.EXPIRED,
                                    OpenPGPSignatureStatus.NO_PUBLIC_KEY,
                                    OpenPGPSignatureStatus.ERROR):
                raise OpenPGPVerificationFailure(
                    err.decode("utf8", errors="backslashreplace"), sig)
            elif sig.sig_status == OpenPGPSignatureStatus.EXPIRED_KEY:
                raise OpenPGPExpiredKeyFailure(
                    err.decode('utf8', errors='backslashreplace'), sig)
            elif sig.sig_status == OpenPGPSignatureStatus.REVOKED_KEY:
                raise OpenPGPRevokedKeyFailure(
                    err.decode('utf8', errors='backslashreplace'), sig)
            else:
                raise OpenPGPUnknownSigFailure(
                    err.decode('utf8', errors='backslashreplace'), sig)

            if not sig.valid_sig:
                raise OpenPGPUnknownSigFailure(
                    err.decode('utf8', errors='backslashreplace'), sig)
            if not sig.trusted_sig:
                raise OpenPGPUntrustedSigFailure(
                    err.decode('utf8', errors='backslashreplace'), sig)

        return sig_list

    def verify_file(self,
                    f: typing.IO[str],
                    require_all_good: bool = True,
                    ) -> OpenPGPSignatureList:
        """
        Perform an OpenPGP verification of Manifest data in open file @f.
        The file should be open in text mode and set at the beginning
        (or start of signed part). Raises an exception if the verification
        fails.

        If require_all_good is True and the file contains multiple OpenPGP
        signatures, all signatures have to be good and trusted in order
        for the verification to succeed. Otherwise, a single good signature
        is considered sufficient.
        """

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--auto-check-trustdb',
             '--status-fd', '1', '--verify'],
            f.read().encode('utf8'))
        return self._process_gpg_verify_output(out, err, require_all_good)

    def verify_detached(self,
                        signature_file: Path,
                        data_file: typing.IO[bytes],
                        require_all_good: bool = True,
                        ) -> OpenPGPSignatureList:
        """
        Verify the file against a detached signature

        Verify the data from data_file against the detached signature
        from signature_file.  data_file should be an open file,
        whereas signature_file should be a Path object.
        Raise an exception if the verification fails.

        If require_all_good is True and the file contains multiple OpenPGP
        signatures, all signatures have to be good and trusted in order
        for the verification to succeed. Otherwise, a single good signature
        is considered sufficient.
        """

        _, out, err = self._spawn_gpg(
            [GNUPG, "--batch", "--auto-check-trustdb",
             "--status-fd", "1", "--verify",
             str(signature_file), "-"],
            stdin_file=data_file)
        return self._process_gpg_verify_output(out, err, require_all_good)

    def clear_sign_file(self, f, outf, keyid=None):
        """
        Create an OpenPGP cleartext signed message containing the data
        from open file @f, and writing it into open file @outf.
        Both files should be open in text mode and set at the appropriate
        position. Raises an exception if signing fails.

        Pass @keyid to specify the key to use. If not specified,
        the implementation will use the default key.
        """

        args = []
        if keyid is not None:
            args += ['--local-user', keyid]
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--clearsign'] + args,
            f.read().encode('utf8'),
            raise_on_error=OpenPGPSigningFailure)

        outf.write(out.decode('utf8'))

    def _spawn_gpg(self, argv, stdin='', env_override={},
                   raise_on_error=None,
                   stdin_file: typing.Optional[typing.IO[bytes]] = None):
        env = os.environ.copy()
        env['TZ'] = 'UTC'
        env.update(env_override)

        if stdin_file is None:
            stdin_file = subprocess.PIPE

        try:
            p = subprocess.Popen(argv,
                                 stdin=stdin_file,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)
        except FileNotFoundError:
            raise OpenPGPNoImplementation('install gpg')

        out, err = p.communicate(stdin)
        if raise_on_error is not None and p.wait() != 0:
            raise raise_on_error(
                err.decode('utf8', errors='backslashreplace'))
        return (p.wait(), out, err)


def _rmtree_error_handler(func, path, exc_info):
    # ignore ENOENT -- it probably means a race condition between
    # us and gpg-agent cleaning up after itself
    # also non-empty directory due to races, and EBUSY for NFS:
    # https://bugs.gentoo.org/684172
    if (not isinstance(exc_info[1], OSError)
            or exc_info[1].errno not in (errno.ENOENT,
                                         errno.ENOTEMPTY,
                                         errno.EEXIST,
                                         errno.EBUSY)):
        raise exc_info[1]


class IsolatedGPGEnvironment(SystemGPGEnvironment):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.

    Remember to close() in order to clean up the temporary directory,
    or use as a context manager (via 'with').
    """

    def __init__(self, debug=False, proxy=None, timeout=None):
        super().__init__(debug=debug)
        self.proxy = proxy
        self.timeout = timeout
        self._home = tempfile.mkdtemp(prefix='gemato.')

        with open(os.path.join(self._home, 'dirmngr.conf'), 'w') as f:
            f.write(f'''# autogenerated by gemato
# honor user's http_proxy setting
honor-http-proxy

# Disable automagically using Tor when running.  This often leads
# to connectivity issues and is unexpected for users.
no-use-tor

# The default of "recursive-resolver" (see "man dirmngr") may cause
# problems with corporate networks, where this is often prohibited.
# It's better to setup the DNS resolver of your choice correctly
# preferably with DNSSEC checks enabled and use the following setting:
standard-resolver

# enable debugging, in case we needed it
log-file {os.path.join(self._home, 'dirmngr.log')}
debug-level guru
''')

            if timeout is not None:
                # GPG doesn't accept sub-second timeouts
                gpg_timeout = math.ceil(timeout)
                f.write(f"""
# respect user-specified timeouts
resolver-timeout {gpg_timeout}
connect-timeout {gpg_timeout}
""")

        with open(os.path.join(self._home, 'gpg-agent.conf'), 'w') as f:
            f.write(f'''# autogenerated by gemato

# avoid any smartcard operations, we are running in isolation
disable-scdaemon

# enable debugging, in case we needed it
log-file {os.path.join(self._home, 'gpg-agent.log')}
debug-level guru
''')

    def __exit__(self, exc_type, exc_value, exc_cb):
        if self._home is not None:
            self.close()

    def clone(self):
        return IsolatedGPGEnvironment(debug=self.debug, proxy=self.proxy,
                                      timeout=self.timeout)

    def close(self):
        if self._home is not None:
            ret, sout, serr = self._spawn_gpg(
                [GNUPGCONF, '--kill', 'all'])
            if ret != 0:
                LOGGER.warning(
                    f'{GNUPGCONF} --kill failed:\n'
                    f'{serr.decode("utf8", errors="backslashescape")}')
            if not self.debug:
                # we need to loop due to ENOTEMPTY potential
                while os.path.isdir(self._home):
                    shutil.rmtree(self._home,
                                  onerror=_rmtree_error_handler)
            else:
                LOGGER.debug(f'GNUPGHOME left for debug purposes: '
                             f'{self._home}')
            self._home = None

    def import_key(self, keyfile, trust=True):
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--import', '--status-fd', '1'],
            keyfile.read(),
            raise_on_error=OpenPGPKeyImportError)

        fprs = set()
        for line in out.splitlines():
            if line.startswith(b'[GNUPG:] IMPORT_OK'):
                fprs.add(line.split(b' ')[3].decode('ASCII'))
        if not fprs:
            raise OpenPGPKeyImportError("No keys imported")

        imported = self.list_keys(list(fprs))
        missing = fprs - {fpr for fpr, uids in imported.items() if uids}
        if missing:
            raise OpenPGPKeyImportError(
                "Import succeeded but no valid key for fingerprints: "
                f"{missing}"
            )

        if trust:
            self._trusted_keys.update(fprs)
            ownertrust = ''.join(f'{fpr}:6:\n' for fpr in fprs).encode('utf8')
            exitst, out, err = self._spawn_gpg(
                [GNUPG, '--batch', '--import-ownertrust'],
                ownertrust,
                raise_on_error=OpenPGPKeyImportError)

    def refresh_keys_wkd(self):
        """
        Attempt to fetch updated keys using WKD.  Returns true if *all*
        keys were successfully found.  Otherwise, returns false.
        """
        if requests is None:
            LOGGER.debug('refresh_keys_wkd(): failing because requests'
                         'module is missing')
            return False

        # list all keys in the keyring
        keys = self.list_keys()
        if not keys:
            LOGGER.debug('refresh_keys_wkd(): no keys found')
            return False
        addrs = set()
        for key, uids in keys.items():
            key_addrs = {
                addr for uid in uids
                if "@" in (addr := email.utils.parseaddr(
                    uid.decode("utf8", errors="replace")
                )[1])
            }
            if not key_addrs:
                LOGGER.debug(
                    f"refresh_keys_wkd(): failing due to no email addresses "
                    f"on key {key}")
                return False
            addrs.update(key_addrs)
        expected_keys = frozenset(keys)

        data = b''
        proxies = {}
        if self.proxy is not None:
            proxies = {
                'http': self.proxy,
                'https': self.proxy,
            }
        for a in addrs:
            url = get_wkd_url(a)
            try:
                resp = requests.get(url, proxies=proxies, timeout=self.timeout)
                resp.raise_for_status()
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.HTTPError,
                    ) as e:
                LOGGER.debug(f'refresh_keys_wkd(): failing due to failed '
                             f'request for {url}: {e}')
                return False
            data += resp.content

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--import', '--status-fd', '1'],
            data,
            raise_on_error=OpenPGPKeyRefreshError)

        imported_keys = set()
        for line in out.splitlines():
            if line.startswith(b'[GNUPG:] IMPORT_OK'):
                fpr = line.split(b' ')[3].decode('ASCII')
                LOGGER.debug(
                    f'refresh_keys_wkd(): import successful for key: {fpr}')
                imported_keys.add(fpr)

        # Need to explicitly ensure all keys were fetched
        # However:
        # - any key MAY appear 0 or more times.
        # - expected keys SHOULD be present.
        # - unexpected keys MAY also be present.
        unexpected_keys = imported_keys.difference(expected_keys)
        if unexpected_keys:
            # we need to delete unexpected keys
            LOGGER.debug(
                f'refresh_keys_wkd(): got unexpected key, will remove: '
                f'{unexpected_keys}')
            # 128x 40-byte fingerprints = 5KiB commandline max
            # If this contains a lot of keys, it should just blow up, but that
            # saves complexity.
            exitst, out, err = self._spawn_gpg(
                [GNUPG, '--batch', '--delete-keys'] + list(unexpected_keys),
                raise_on_error=OpenPGPKeyRefreshError)

        not_updated_keys = expected_keys.difference(imported_keys)
        if not_updated_keys:
            LOGGER.debug(
                f'refresh_keys_wkd(): failing due to non-updated keys: '
                f'{not_updated_keys}')
            return False

        return True

    def refresh_keys_keyserver(self, keyserver=None):
        ks_args = []
        if keyserver is not None:
            ks_args = ['--keyserver', keyserver]

        expected_fprs = set(self.list_keys())
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--refresh-keys', '--status-fd', '1'] + ks_args,
            raise_on_error=OpenPGPKeyRefreshError)

        imported_fprs = set()
        for line in out.splitlines():
            if line.startswith(b'[GNUPG:] IMPORT_OK'):
                imported_fprs.add(line.split(b' ')[3].decode('ASCII'))

        if imported_fprs != expected_fprs:
            extra_keys = imported_fprs - expected_fprs
            missing_keys = expected_fprs - imported_fprs
            if extra_keys:
                raise OpenPGPKeyRefreshError(
                    f"Keyserver update injected additional keys: {extra_keys}"
                )
            if missing_keys:
                raise OpenPGPKeyRefreshError(
                    f"Keyserver is missing keys: {missing_keys}"
                )

    def refresh_keys(self, allow_wkd=True, keyserver=None):
        LOGGER.debug(f'refresh_keys(allow_wkd={allow_wkd}, '
                     f'keyserver={keyserver}) called')

        if allow_wkd and self.refresh_keys_wkd():
            return

        self.refresh_keys_keyserver(keyserver=keyserver)

    @property
    def home(self):
        assert self._home is not None
        return self._home

    def _spawn_gpg(self, *args, **kwargs):
        env_override = {'GNUPGHOME': self.home}
        if self.proxy is not None:
            env_override['http_proxy'] = self.proxy
        assert 'env_override' not in kwargs
        kwargs['env_override'] = env_override
        return super()._spawn_gpg(*args, **kwargs)


class PGPyEnvironment:
    """Stand-alone environment using pgpy library"""

    __slots__ = ['debug', 'keyring', 'proxy']

    def __init__(self, debug=False, proxy=None, timeout=None):
        if pgpy is None:
            raise OpenPGPNoImplementation('install PGPy')
        self.debug = debug
        self.keyring = pgpy.PGPKeyring()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        pass

    def close(self):
        pass

    def import_key(self, keyfile):
        with warnings.catch_warnings(record=True) as warns:
            try:
                key_res = pgpy.PGPKey.from_blob(keyfile.read())
            except ValueError as e:
                raise OpenPGPKeyImportError(
                    f'OpenPGP key import failed: {e}')
        fprs = []
        for k in key_res[1].values():
            fprs.extend(self.keyring.load(k))

        for w in warns:
            if str(w.message) == 'Incorrect crc24':
                raise OpenPGPKeyImportError(
                    f'OpenPGP key import failed: {w.message}')

        for fpr in fprs:
            with self.keyring.key(fpr) as k:
                if k.parent is not None:
                    try:
                        verifies = k.parent.verify(k)
                    except pgpy.errors.PGPError:
                        LOGGER.debug(
                            f'Rejecting subkey {fpr} due to missing sig')
                        self.keyring.unload(k)
                    else:
                        if not verifies:
                            LOGGER.debug(
                                f'Rejecting subkey {fpr} since parent '
                                f'key signature does not check out')
                            self.keyring.unload(k)
                for uid in k.userids:
                    if uid.selfsig is None:
                        raise OpenPGPKeyImportError(
                            f'Self-signature on {uid} missing')
                    if not k.verify(uid):
                        raise OpenPGPKeyImportError(
                            f'Self-signature on {uid} does not verify')

    def verify_file(self, f):
        msg = pgpy.PGPMessage.from_blob(f.read())
        assert msg.is_signed
        assert len(msg.signatures) == 1
        assert len(msg.signers) == 1

        signer, = msg.signers
        try:
            with self.keyring.key(signer) as k:
                pk = k
                if k.parent is not None:
                    pk = k.parent
                assert pk.parent is None

                vr = k.verify(msg)
                if not vr:
                    raise OpenPGPVerificationFailure(
                        f'Bad signature made by key {k.fingerprint}')
                now = datetime.datetime.now(datetime.timezone.utc)
                sig_expire = msg.signatures[0].expires_at
                if sig_expire is not None and sig_expire < now:
                    raise OpenPGPVerificationFailure(
                        f'Signature expired at {msg.signatures[0].expires_at}')
                if k.expires_at is not None and k.expires_at < now:
                    raise OpenPGPExpiredKeyFailure(
                        f'Key {k.fingerprint} expired at {k.expires_at}')
                if pk.expires_at is not None and pk.expires_at < now:
                    raise OpenPGPExpiredKeyFailure(
                        f'Primary key {pk.fingerprint} expired '
                        f'at {k.expires_at}')
                if list(k.revocation_signatures):
                    raise OpenPGPRevokedKeyFailure(
                        f'Key {pk.fingerprint} was revoked')
                if list(pk.revocation_signatures):
                    raise OpenPGPRevokedKeyFailure(
                        f'Primary key {pk.fingerprint} was revoked')
                return OpenPGPSignatureData(
                    k.fingerprint,
                    msg.signatures[0].created,
                    msg.signatures[0].expires_at,
                    pk.fingerprint)
        except KeyError:
            raise OpenPGPVerificationFailure(
                f'Key {signer} not in keyring')


OpenPGPSystemEnvironment = SystemGPGEnvironment
OpenPGPEnvironment = IsolatedGPGEnvironment
