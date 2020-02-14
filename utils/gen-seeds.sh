#!/bin/bash

set -eu

CA='ca.pem'
CURVE='secp256k1'
DIGEST='sha256'
NUMBER='10'
SUBJECT=''
CASUBJECT=''

# $1: key
# $2: csr
signcsr() {
    openssl req -x509 -"$DIGEST" -days 365 -key "$1" -in "$2"
}

# $1: key
# $2: subject
newcsr() {
    openssl req -new -"$DIGEST" -key "$1" -subj "$2"
}

newkey() {
    openssl ecparam -name "$CURVE" -genkey -noout
}

usage() {
    echo "usage: $(basename "$0") [-cdnasSh]"
    echo ""
    echo "options:"
    echo " -a   Eliptic curve alogrithm, see openssl ecparam -list_curves"
    echo " -d   Digest algorithm to use, e.g. sha256"
    echo " -n   Number of certificates to create"
    echo " -s   Specify subject for peer cert in openssl syntax: /CN=foo"
    echo " -S   Specify subject for CA in openssl syntax: /CN=foo"
    echo " -h   Show this page and exit"
}

die() {
    echo "error: $*"
    exit 1
}

main() {
    local cacsr
    local cacert

    if [[ -r "$CA" ]]; then
        die "ca file already exist: $CA"
    fi
    if [[ -z "$SUBJECT" ]]; then
        die "please set -s"
    fi
    if [[ -z "$CASUBJECT" ]]; then
        die "please set -S"
    fi

    newkey > "$CA"
    cacsr="$(mktemp)"
    cacert="$(mktemp)"

    newcsr "$CA" "$CASUBJECT" > "$cacsr"
    signcsr "$CA" "$cacsr" >> "$cacert"
    cat "$cacert" >> "$CA"
    rm "$cacsr"
    rm "$cacert"

    for (( i=0; i<NUMBER; i++)); do
        local key
        local cert
        local csr

        key="key-$i.pem"
        newkey > "$key"

        csr="$(mktemp)"
        newcsr "$key" "$SUBJECT" > "$csr"

        cert="cert-$i.pem"
        signcsr "$CA" "$csr" > "$cert"
        cat "$key" >> "$cert"
        rm "$csr"
        rm "$key"
    done
}

while getopts "c:d:n:a:s:S:h" arg; do
    case "$arg" in
        a)  CURVE="$OPTARG";;
        d)  DIGEST="$OPTARG";;
        n)  NUMBER="$OPTARG";;
        s)  SUBJECT="$OPTARG";;
        S)  CASUBJECT="$OPTARG";;
        h)  usage && exit 0;;
        *)  usage && exit 1;;
    esac
done

main
