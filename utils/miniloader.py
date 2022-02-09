#!/usr/bin/env python3

import sys
from pathlib import Path

from cryptography import x509


def main():
    for file in sys.stdin:
        path = Path(file.strip())
        raw = path.read_bytes()
        try:
            x509.load_pem_x509_certificate(raw)
        except Exception as e:
            print(f"{path}: {e}")


if __name__ == "__main__":
    main()
