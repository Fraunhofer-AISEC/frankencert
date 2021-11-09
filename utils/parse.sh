#!/usr/bin/env bash

while read -r line; do
    openssl x509 -text -noout -in "$line" >> "parsed_stuff.txt"
done < "$1"
