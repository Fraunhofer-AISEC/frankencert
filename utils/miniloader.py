#!/usr/bin/env python3

import sys
from pathlib import Path

from cryptography import x509


def main():
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    x509.load_pem_x509_certificate(raw)


if __name__ == "__main__":
    main()
