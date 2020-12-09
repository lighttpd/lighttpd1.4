#!/bin/sh

CERT_PEM="$1"   # input (cert.pem)
CHAIN_PEM="$2"  # input (chain.pem)
OCSP_DER="$3"   # output symlink (staple.der)

OCSP_TMP=""     # temporary file

if [ -z "$CERT_PEM" ] || [ -z "$CHAIN_PEM" ] || [ -z "$OCSP_DER" ] \
   || [ ! -f "$CERT_PEM" ] || [ ! -f "$CHAIN_PEM" ]; then
    echo 1>&2 "usage: cert-staple.sh cert.pem chain.pem staple.der"
    exit 1
fi

errexit() {
    [ -n "$OCSP_TMP" ] && rm -f "$OCSP_TMP"
    exit 1
}

# get URI of OCSP responder from certificate
OCSP_URI=$(openssl x509 -in "$CERT_PEM" -ocsp_uri -noout)
[ $? = 0 ] && [ -n "$OCSP_URI" ] || exit 1

# exception for (unsupported, end-of-life) older versions of OpenSSL
OCSP_HOST=
OPENSSL_VERSION=$(openssl version)
if [ "${OPENSSL_VERSION}" != "${OPENSSL_VERSION#OpenSSL 1.0.}" ]; then
    # get authority from URI
    OCSP_HOST=$(echo "$OCSP_URI" | cut -d/ -f3)
fi

# get OCSP response from OCSP responder
OCSP_TMP="$OCSP_DER.$$"
OCSP_RESP=$(openssl ocsp -issuer "$CHAIN_PEM" -cert "$CERT_PEM" -respout "$OCSP_TMP" -noverify -no_nonce -url "$OCSP_URI" ${OCSP_HOST:+-header Host "$OCSP_HOST"})
[ $? = 0 ] || errexit

# parse OCSP response from OCSP responder
#
#$CERT_PEM: good
#        This Update: Jun  5 21:00:00 2020 GMT
#        Next Update: Jun 12 21:00:00 2020 GMT

ocsp_status="$(printf %s "$OCSP_RESP" | head -1)"
[ "$ocsp_status" = "$CERT_PEM: good" ] || errexit

next_update="$(printf %s "$OCSP_RESP" | grep 'Next Update:')"
next_date="$(printf %s "$next_update" | sed 's/.*Next Update: //')"
[ -n "$next_date" ] || errexit
ocsp_expire=$(date -d "$next_date" +%s)

# validate OCSP response
ocsp_verify=$(openssl ocsp -issuer "$CHAIN_PEM" -verify_other "$CHAIN_PEM" -cert "$CERT_PEM" -respin "$OCSP_TMP" -no_nonce -out /dev/null 2>&1)
[ "$ocsp_verify" = "Response verify OK" ] || errexit

# rename and update symlink to install OCSP response to be used in OCSP stapling
OCSP_OUT="$OCSP_DER.$ocsp_expire"
mv "$OCSP_TMP" "$OCSP_OUT" || errexit
OCSP_TMP=""
ln -sf "${OCSP_OUT##*/}" "$OCSP_DER" || errexit

# debug: display text output of OCSP .der file
#openssl ocsp -respin "$OCSP_DER" -resp_text -noverify

# remove old OCSP responses which have expired
now=$(date +%s)
for i in "$OCSP_DER".*; do
    ts="${i#${OCSP_DER}.}"
    if [ -n "$ts" ] && [ "$ts" -lt "$now" ]; then
        rm -f "$i"
    fi
done
