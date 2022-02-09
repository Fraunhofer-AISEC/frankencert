#!/usr/bin/env python3

import asyncio
import argparse
import base64
import gzip
import json
import multiprocessing
import signal
import sys
from asyncio import to_thread
from datetime import datetime
from pathlib import Path
from subprocess import PIPE
from typing import Any, Optional, Iterable

import aiosqlite
from aiofiles.os import stat
from aiofiles.ospath import exists, isdir


SCHEMA_VERSION = 0
SCHEMA = """
CREATE TABLE version (
    version integer
) STRICT;

CREATE TABLE scan_run (
    id integer primary key,
    command text check(json_valid(command)),
    start_time real not null,
    end_time real,
    exit_code int
) STRICT;

CREATE TABLE scan_result (
    id integer primary key,
    run int not null references scan_run(id) on update cascade on delete cascade,
    loader_path text not null,
    start_time real not null,
    end_time real not null,
    cert blob,
    exit_code int not null,
    stdout blob,
    stderr blob
) STRICT;
"""


class Runner:
    def __init__(self, db_path: Path, cert_file: Path, loaders: list[Path]) -> None:
        self.db_path = db_path
        self.cert_file = cert_file
        self.loader_paths = loaders
        self.loaders: dict[str, asyncio.subprocess.Process] = {}
        self.run_id: Optional[int] = None
        self.mutexes: dict[str, asyncio.Lock] = {}

    async def commit(self) -> None:
        await self.db.commit()

    async def close(self) -> None:
        await self.db.commit()
        await self.db.close()

    async def _do_sql_single(self, sql: str, args: Optional[Iterable] = None) -> None:
        if args is not None:
            await self._do_sql_multiple([sql], {0: args})
        else:
            await self._do_sql_multiple([sql])

    async def _do_sql_multiple(
        self, sql: list[str], args: Optional[dict[int, Iterable[Any]]] = None
    ) -> None:
        for i, line in enumerate(sql):
            if args is not None and i in args:
                await self.cur.execute(line, args[i])
            else:
                await self.cur.execute(line)

    async def _db_connect(self) -> None:
        self.db = await aiosqlite.connect(self.db_path)
        self.cur = await self.db.cursor()
        sql = [
            "PRAGMA foreign_keys = ON;",
            f"PRAGMA threads = {multiprocessing.cpu_count()};",
        ]
        await self._do_sql_multiple(sql)

    async def db_create(self) -> None:
        await self._db_connect()
        await self.cur.executescript(SCHEMA)
        await self.cur.execute(
            "INSERT INTO version(version) VALUES(?)",
            (SCHEMA_VERSION,),
        )

    async def db_connect(self) -> None:
        await self._db_connect()
        await self._do_sql_single("SELECT version from version;")
        res = await self.cur.fetchone()
        if res is None:
            raise RuntimeError("no schema version")
        if (schema_version := res[0]) != SCHEMA_VERSION:
            raise RuntimeError(f"unsupported schema version: {schema_version}")

    async def run_add(self, command: list[str], start_time: datetime) -> None:
        await self._do_sql_single(
            "INSERT INTO scan_run(command, start_time) VALUES(?, ?)",
            (json.dumps(command), start_time.timestamp()),
        )
        self.run_id = self.cur.lastrowid

    async def run_finish(self, end_time: datetime, exit_code: int) -> None:
        assert self.run_id, "run_id is not set"
        await self._do_sql_single(
            "UPDATE scan_run SET end_time=?, exit_code=? WHERE id==?",
            (end_time.timestamp(), exit_code, self.run_id),
        )

    async def result_add(
        self,
        loader_path: Path,
        start_time: datetime,
        end_time: datetime,
        cert: bytes,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> int:
        assert self.run_id, "run_id is not set"
        await self._do_sql_single(
            """INSERT INTO scan_result(
                    run,
                    loader_path,
                    start_time,
                    end_time,
                    exit_code,
                    cert,
                    stdout,
                    stderr
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.run_id,
                str(loader_path),
                start_time.timestamp(),
                end_time.timestamp(),
                exit_code,
                cert,
                stdout,
                stderr,
            ),
        )
        return self.cur.lastrowid

    async def _testrun_call(self, loader: str, cert: bytes) -> None:
        assert self.run_id, "run_id is not set"
        start_time = datetime.now()
        p = self.loaders[loader]
        assert p.stdin, "stdin of loader is not connected"
        assert p.stdout, "stdout of loader is not connected"
        assert p.stderr, "stderr of loader is not connected"

        p.stdin.write(cert)
        await p.stdin.drain()
        end_time = datetime.now()

        print("boo")
        stderr = await p.stderr.feed_data read(64 * 1024)
        print("boo")
        stdout = await p.stdout.readline()
        ipc_json = json.loads(stdout)
        returncode = ipc_json["return_code"]
        print(returncode)

        await self.result_add(
            Path(loader),
            start_time,
            end_time,
            cert,
            returncode,
            stdout,
            stderr,
        )

    async def testrun_call(self, loader: str, cert: bytes) -> None:
        async with self.mutexes[loader]:
            await self._testrun_call(loader, cert)

    async def start_loaders(self) -> None:
        for path in self.loader_paths:
            p = await asyncio.create_subprocess_exec(
                path, stdout=PIPE, stderr=PIPE, stdin=PIPE
            )
            self.loaders[str(path)] = p
            self.mutexes[str(path)] = asyncio.Lock()

    async def stop_loaders(self) -> None:
        for k, v in self.loaders.items():
            print(f"killing: {k}")
            v.terminate()
            await v.wait()

    async def process_tests(self) -> None:
        await self.run_add(sys.argv, datetime.now())
        await self.start_loaders()

        with await to_thread(gzip.open, self.cert_file, "r") as f:
            while True:
                line = await to_thread(f.readline)
                if line == b"":
                    break
                cert = parse_line(line.decode())

                for loader in self.loaders:
                    await self.testrun_call(loader, cert)


def parse_line(line: str) -> bytes:
    _, cert = line.split(",", maxsplit=1)
    b = base64.standard_b64decode(cert)
    out = base64.standard_b64encode(b)
    return b"-----BEGIN CERTIFICATE-----\n" + out + b"\n-----END CERTIFICATE-----\n"


async def load_loaders(path: Path) -> list[Path]:
    res = []
    for loader in path.iterdir():
        if await isdir(loader) or (await stat(loader)).st_mode & 0o100 != 0o100:
            continue
        res.append(loader)
    return res


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--loader-dir", type=Path, help="Path to executables used as loaders"
    )
    parser.add_argument(
        "--cert-file", type=Path, help="Path to certificat file to be loaded"
    )
    parser.add_argument("--db", type=Path, help="Path to sqlite database")
    args = parser.parse_args()

    loaders = await load_loaders(args.loader_dir)
    runner = Runner(args.db, args.cert_file, loaders)
    if await exists(args.db):
        await runner.db_connect()
    else:
        await runner.db_create()

    exit_code = 0

    try:
        await runner.process_tests()
    except Exception:
        raise
    except KeyboardInterrupt:
        exit_code = 128 + signal.SIGINT
    finally:
        await runner.run_finish(datetime.now(), exit_code)
        await runner.close()

    sys.exit(exit_code)


if __name__ == "__main__":
    asyncio.run(main())
