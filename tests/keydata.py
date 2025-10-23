# gemato: OpenPGP key data for tests
# (c) 2017-2025 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path


data_dir = Path(__file__).parent / "data"


def break_sig(sig):
    """Return signature packet mangled to mismatch the signed key"""
    return sig[:-1] + b'\x55'


def _(path: str) -> bytes:
    return data_dir.joinpath(path).read_bytes()


def F(path: str) -> str:
    return data_dir.joinpath(path).read_text().strip()


def T(path: str) -> str:
    return data_dir.joinpath(path).read_text()


PUBLIC_KEY = _("first-key/pub")
SECRET_KEY = _("first-key/secret")
PUBLIC_SUBKEY = _("first-key/subkey")
UID = _("first-key/uid")
UID_NOEMAIL = _("first-key/uid-noemail")
UID_NONUTF = _("first-key/uid-nonutf")

PUBLIC_KEY_SIG = _("first-key/uid-sig")
PUBLIC_KEY_NOEMAIL_SIG = _("first-key/uid-noemail-sig")
PUBLIC_KEY_NONUTF_SIG = _("first-key/uid-nonutf-sig")
PUBLIC_SUBKEY_SIG = _("first-key/subkey-sig")
EXPIRED_KEY_SIG = _("first-key/expired-sig")
REVOCATION_SIG = _("first-key/revocation-sig")
UNEXPIRE_SIG = _("first-key/unexpire-sig")

OTHER_PUBLIC_KEY = _("other-key/pub")
OTHER_PUBLIC_KEY_UID = _("other-key/uid")
OTHER_PUBLIC_KEY_SIG = _("other-key/uid-sig")

SECOND_PUBLIC_KEY = _("second-key/pub")
SECOND_SECRET_KEY = _("second-key/secret")
SECOND_UID = _("second-key/uid")
SECOND_KEY_SIG = _("second-key/uid-sig")

VALID_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
EXPIRED_PUBLIC_KEY = PUBLIC_KEY + UID + EXPIRED_KEY_SIG
REVOKED_PUBLIC_KEY = PUBLIC_KEY + REVOCATION_SIG + UID + PUBLIC_KEY_SIG
OLD_UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + UNEXPIRE_SIG

PRIVATE_KEY = SECRET_KEY + UID + PUBLIC_KEY_SIG
PRIVATE_KEY_ID = F("first-key/private-key-id.txt")

KEY_FINGERPRINT = F("first-key/fpr.txt")
SUBKEY_FINGERPRINT = F("first-key/sub-fpr.txt")
OTHER_KEY_FINGERPRINT = F("other-key/fpr.txt")
SECOND_KEY_FINGERPRINT = F("second-key/fpr.txt")

OTHER_VALID_PUBLIC_KEY = (OTHER_PUBLIC_KEY + OTHER_PUBLIC_KEY_UID +
                          OTHER_PUBLIC_KEY_SIG)

VALID_KEY_NOEMAIL = PUBLIC_KEY + UID_NOEMAIL + PUBLIC_KEY_NOEMAIL_SIG
VALID_KEY_NONUTF = PUBLIC_KEY + UID_NONUTF + PUBLIC_KEY_NONUTF_SIG

VALID_KEY_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                    PUBLIC_SUBKEY_SIG)

FORGED_PUBLIC_KEY = PUBLIC_KEY + UID + break_sig(PUBLIC_KEY_SIG)
FORGED_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                 break_sig(PUBLIC_SUBKEY_SIG))
FORGED_UNEXPIRE_KEY = (PUBLIC_KEY + UID + EXPIRED_KEY_SIG +
                       break_sig(UNEXPIRE_SIG))

UNSIGNED_PUBLIC_KEY = PUBLIC_KEY + UID
UNSIGNED_SUBKEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY

COMBINED_PUBLIC_KEYS = OTHER_VALID_PUBLIC_KEY + VALID_PUBLIC_KEY

SECOND_VALID_PUBLIC_KEY = SECOND_PUBLIC_KEY + SECOND_UID + SECOND_KEY_SIG

TWO_SIGNATURE_PUBLIC_KEYS = VALID_PUBLIC_KEY + SECOND_VALID_PUBLIC_KEY
TWO_KEYS_ONE_EXPIRED = EXPIRED_PUBLIC_KEY + SECOND_VALID_PUBLIC_KEY


if __name__ == "__main__":
    import argparse
    import sys

    argp = argparse.ArgumentParser()
    argp.add_argument("variable",
                      nargs="+",
                      choices=sorted(x for x in globals() if x[0].isupper()),
                      help="Variables to print")
    args = argp.parse_args()

    sys.stdout.buffer.write(b"".join(globals()[x] for x in args.variable))
