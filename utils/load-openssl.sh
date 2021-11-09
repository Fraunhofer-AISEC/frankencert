#!/usr/bin/env bash

find "$1" -name '*.pem' | while read file; do
    if ! openssl x509 -in "$file" -text -noout > /dev/null; then
        echo "$file: failed" 
    fi
done
