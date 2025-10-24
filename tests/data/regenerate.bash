#!/bin/bash

set -e -x

: "${GNUPG:=gpg}"
: "${GPGSPLIT:=gpgsplit}"

GPG="${GNUPG} --batch --yes --passphrase="
FIRST_UID="gemato test key <gemato@example.com>"
FIRST_UID_NOEMAIL="gemato test key"
FIRST_UID_NONUTF=$'gemat\xf6 test key <gemato@example.com>'
SECOND_UID="Second gemato test identity <second@example.com>"

# base time for generation
FAKETIME1='faketime 2020-01-01'
# some time after keys expire
FAKETIME2='faketime 2024-01-01'
FAKETIME3='faketime 2025-01-01'

rm -rf tmp
mkdir tmp
chmod go-rwx tmp
export GNUPGHOME=${PWD}/tmp
export TZ=UTC

cd tmp

# first key (non-expired) with different UIDs
${FAKETIME1} ${GPG} --quick-generate-key "${FIRST_UID_NOEMAIL}" ed25519 sign 0
FIRST_KEY_FPR=$(${GPG} --list-keys --with-colons | grep ^fpr | cut -d: -f10)
[[ -n ${FIRST_KEY_FPR} ]]
${GPG} --export ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000002*.user_id ../first-key/uid-noemail
mv 000003*.sig ../first-key/uid-noemail-sig

${FAKETIME1} ${GPG} --quick-add-uid "${FIRST_UID_NOEMAIL}" "${FIRST_UID_NONUTF}"
${FAKETIME1} ${GPG} --quick-revoke-uid "${FIRST_UID_NOEMAIL}" "${FIRST_UID_NOEMAIL}"
${GPG} --export --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000002*.user_id ../first-key/uid-nonutf
mv 000003*.sig ../first-key/uid-nonutf-sig

${FAKETIME1} ${GPG} --quick-add-uid "${FIRST_UID_NONUTF}" "${FIRST_UID}"
${FAKETIME1} ${GPG} --quick-revoke-uid "${FIRST_UID_NONUTF}" "${FIRST_UID_NONUTF}"

# signatures with the first key
${FAKETIME1} ${GPG} --clear-sign --output=../Manifest.asc ../Manifest
${FAKETIME1} ${GPG} --clear-sign --default-sig-expire=1m --output=../Manifest.asc-expired ../Manifest
${FAKETIME2} ${GPG} --clear-sign --output=../Manifest.asc-post-expiration ../Manifest
${FAKETIME2} ${GPG} --detach-sign --output=sig1 ../Manifest

# create a subkey and sign with it
${FAKETIME1} ${GPG} --quick-add-key "${FIRST_KEY_FPR}" ed25519 sign 0
FIRST_SUBKEY_FPR=$(${GPG} --list-keys --with-colons | grep ^fpr | tail -n 1 | cut -d: -f10)
${FAKETIME1} ${GPG} --clear-sign --output=../Manifest.asc-subkey-signed ../Manifest

# export the base key and subkey
${GPG} --export --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
${GPG} --export-secret-keys --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000001*.public_key ../first-key/pub
mv 000001*.secret_key ../first-key/secret
mv 000002*.user_id ../first-key/uid
mv 000003*.sig ../first-key/uid-sig
mv 000004*.public_subkey ../first-key/subkey
mv 000005*.sig ../first-key/subkey-sig
echo "${FIRST_KEY_FPR}" > ../first-key/fpr.txt
echo "${FIRST_SUBKEY_FPR}" > ../first-key/sub-fpr.txt

# prepare the expiration / revocation signatures now
${FAKETIME1} ${GPG} --quick-set-expire "${FIRST_KEY_FPR}" 3y
${GPG} --export --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000003*.sig ../first-key/expired-sig

${FAKETIME2} ${GPG} --quick-set-expire "${FIRST_KEY_FPR}" 3y
${GPG} --export --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000003*.sig ../first-key/unexpire-sig

sed -i -e 's@^:@@' "openpgp-revocs.d/${FIRST_KEY_FPR}.rev"
${FAKETIME2} ${GPG} --import "openpgp-revocs.d/${FIRST_KEY_FPR}.rev"
${GPG} --export --export-filter=keep-uid=revoked==0 ${FIRST_KEY_FPR} | ${GPGSPLIT}
mv 000002*.sig ../first-key/revocation-sig

${GPG} --delete-secret-keys "${FIRST_KEY_FPR}"
${GPG} --delete-key "${FIRST_KEY_FPR}"

# other key (used only for WKD tests)
${FAKETIME1} ${GPG} --quick-generate-key "${FIRST_UID}" ed25519 sign 0
OTHER_KEY_FPR=$(${GPG} --list-keys --with-colons | grep ^fpr | cut -d: -f10)
[[ -n ${OTHER_KEY_FPR} ]]

${GPG} --export ${OTHER_KEY_FPR} | ${GPGSPLIT}
mv 000001*.public_key ../other-key/pub
mv 000002*.user_id ../other-key/uid
mv 000003*.sig ../other-key/uid-sig
echo "${OTHER_KEY_FPR}" > ../other-key/fpr.txt
${GPG} --delete-secret-keys "${OTHER_KEY_FPR}"
${GPG} --delete-key "${OTHER_KEY_FPR}"

# second key (with a different UID)
${FAKETIME1} ${GPG} --quick-generate-key "${SECOND_UID}" ed25519 sign 0
SECOND_KEY_FPR=$(${GPG} --list-keys --with-colons | grep ^fpr | cut -d: -f10)
[[ -n ${SECOND_KEY_FPR} ]]

${GPG} --export ${SECOND_KEY_FPR} | ${GPGSPLIT}
${GPG} --export-secret-keys ${SECOND_KEY_FPR} | ${GPGSPLIT}
mv 000001*.public_key ../second-key/pub
mv 000001*.secret_key ../second-key/secret
mv 000002*.user_id ../second-key/uid
mv 000003*.sig ../second-key/uid-sig
echo "${SECOND_KEY_FPR}" > ../second-key/fpr.txt
${FAKETIME1} ${GPG} --detach-sign --output=sig2 ../Manifest
${FAKETIME1} ${GPG} --clear-sign --output=Manifest.asc-second ../Manifest
${GPG} --delete-secret-keys "${SECOND_KEY_FPR}"
${GPG} --delete-key "${SECOND_KEY_FPR}"

# combine the two signatures
cat sig1 sig2 > ../two-signatures.bin
{
	sed -ne '/^-----BEGIN PGP SIGNATURE-----$/,$p' ../Manifest.asc-post-expiration | gpg --dearmor
	sed -ne '/^-----BEGIN PGP SIGNATURE-----$/,$p' Manifest.asc-second | gpg --dearmor
} > two-cleartexts.bin
${GPG} --enarmor --output two-cleartexts.asc two-cleartexts.bin
{
	sed -n -e '1,/^-----BEGIN PGP SIGNATURE-----$/p' ../Manifest.asc
	sed -n -e '/^$/,/^=/p' two-cleartexts.asc
	sed -n -e '/^-----END PGP SIGNATURE-----$/,$p' ../Manifest.asc
} > ../Manifest.asc-two-signatures
