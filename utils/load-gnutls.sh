#!/usr/bin/env bash

find "$1" -name '*.pem' | while read file; do
    if ! certtool --infile="$file" --certificate-info > /dev/null 2>&1; then
        echo "$file: failed" 
    fi
done
