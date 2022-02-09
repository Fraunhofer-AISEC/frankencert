#!/usr/bin/env python3

import hashlib
import sys
from datetime import datetime
from pathlib import Path


def main():
    artifacts_dir = Path(".")
    artifacts_dir = artifacts_dir.joinpath(f"groups-{datetime.now().timestamp()}")

    for line in sys.stdin:
        line = line.strip()
        parts = line.split(":", maxsplit=1)
        path = Path(parts[0])
        error_msg = parts[1]
        checksum = hashlib.sha256(error_msg.encode())

        group_dir = artifacts_dir.joinpath(checksum.hexdigest())
        results_file = group_dir.joinpath("RESULTS")
        if not group_dir.exists():
            group_dir.mkdir(parents=True)
            error_file = group_dir.joinpath("ERROR")
            error_file.write_text(f"{error_msg}\n")

        with results_file.open("a") as f:
            f.write(f"{path}\n")


if __name__ == "__main__":
    main()
