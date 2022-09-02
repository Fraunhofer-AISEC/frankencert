#!/usr/bin/env bash

DB="$1"

sqlite3 -json "$DB" 'SELECT loader, json_extract("in_data", "$.in.stdin") AS stdin, json_extract("out_data", "$.out.stdout") AS stdout, json_extract("out_data", "$.out.stderr") AS stderr FROM scan_result WHERE success == FALSE;'
sqlite3 -json "$DB" 'SELECT loader, count(*) AS n FROM scan_result WHERE success == false GROUP BY loader;'
