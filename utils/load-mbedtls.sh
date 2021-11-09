#!/usr/bin/env bash

set -eu

find "$1" -name '*.pem' | while read file; do
	if ! mbedtls_cert_app mode=file filename="$file" >/dev/null; then
		echo "$file: failed" >&2
	fi
done
