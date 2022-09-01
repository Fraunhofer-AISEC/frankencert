from __future__ import annotations

import argparse
import json
import multiprocessing
import sqlite3
import subprocess
import sys
import warnings
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime
from pathlib import Path
from subprocess import PIPE, Popen
from typing import cast

from cryptography.utils import CryptographyDeprecationWarning
from gallia.config import ConfigType, load_config_file
from gallia.command import Script

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from cryptography import x509

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
    loader text not null,
    start_time real not null,
    end_time real not null,
    in_data text check(json_valid(in_data)),
    out_data text check(json_valid(out_data))
) STRICT;
"""


class BasePlugin(ABC):
    @abstractmethod
    def run(self, cert: bytes) -> None | str:
        ...

    def __str__(self) -> str:
        return self.__class__.__name__

    def __repr__(self) -> str:
        return str(self)


class IPCPlugin(BasePlugin):
    def __init__(self, path: Path):
        self.path = path
        self.loader = Popen([self.path], stdout=PIPE, stdin=PIPE, text=True, bufsize=1)

    def run(self, cert: bytes) -> None | str:
        assert self.loader.stdout
        assert self.loader.stdin

        data = json.dumps({"in": cert.decode()})
        self.loader.stdin.write(data + "\n")
        res = json.loads(self.loader.stdout.readline())
        if "out" in res and res["out"]:
            return str(res["out"])
        return None

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.path})"


class GNUTLS_Plugin(BasePlugin):
    def run(self, cert: bytes) -> None | str:
        p = subprocess.run(
            [
                "certtool",
                "--certificate-info",
                "--load-certificate",
                "/dev/stdin",
            ],
            input=cert,
            capture_output=True,
        )
        if p.returncode != 0:
            return p.stderr.decode().strip()
        return None


class PythonPlugin(BasePlugin):
    def run(self, cert: bytes) -> None | str:
        try:
            x509.load_pem_x509_certificate(cert)
            return None
        except Exception as e:
            return str(e)


class DBHandler:
    def __init__(self, path: Path, db: sqlite3.Connection, cur: sqlite3.Cursor) -> None:
        self.path = path
        self.db = db
        self.cur = cur

    def commit(self) -> None:
        self.db.commit()

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    def create(self) -> None:
        self.cur.executescript(SCHEMA)
        self.cur.execute(
            "INSERT INTO version(version) VALUES(?)",
            (SCHEMA_VERSION,),
        )

    @classmethod
    def connect(cls, path: Path) -> DBHandler:
        create = False if path.exists() else True

        db = sqlite3.connect(path)
        cur = db.cursor()
        # https://phiresky.github.io/blog/2020/sqlite-performance-tuning/
        sql = [
            "PRAGMA foreign_keys = ON;",
            f"PRAGMA threads = {multiprocessing.cpu_count()};",
            "PRAGMA journal_mode = WAL;",
            "PRAGMA synchronous = normal;",
            "PRAGMA temp_store = memory;",
        ]
        for line in sql:
            cur.execute(line)

        if create:
            cur.executescript(SCHEMA)
            cur.execute(
                "INSERT INTO version(version) VALUES(?)",
                (SCHEMA_VERSION,),
            )
            db.commit()
        else:
            cur.execute("SELECT version from version;")
            res = cur.fetchone()
            if res is None:
                raise RuntimeError("no schema version")
            if (schema_version := res[0]) != SCHEMA_VERSION:
                raise RuntimeError(f"unsupported schema version: {schema_version}")

        return cls(path, db, cur)

    def run_add(self, command: list[str], start_time: datetime) -> None:
        self.cur.execute(
            "INSERT INTO scan_run(command, start_time) VALUES(?, ?)",
            (json.dumps(command), start_time.timestamp()),
        )
        self.run_id = self.cur.lastrowid

    def run_finish(self, end_time: datetime, exit_code: int) -> None:
        assert self.run_id, "run_id is not set"
        self.cur.execute(
            "UPDATE scan_run SET end_time=?, exit_code=? WHERE id==?",
            (end_time.timestamp(), exit_code, self.run_id),
        )

    def result_add(
        self,
        loader: str,
        start_time: datetime,
        end_time: datetime,
        in_data: dict,
        out_data: dict,
    ) -> int:
        assert self.run_id, "run_id is not set"
        self.cur.execute(
            """INSERT INTO scan_result(
                    run,
                    loader,
                    start_time,
                    end_time,
                    in_data,
                    out_data
                ) VALUES(?, ?, ?, ?, ?, ?)""",
            (
                self.run_id,
                loader,
                start_time.timestamp(),
                end_time.timestamp(),
                json.dumps(in_data),
                json.dumps(out_data),
            ),
        )
        assert self.cur.lastrowid
        return self.cur.lastrowid


def parse_line(line: str) -> bytes:
    _, cert = line.split(",", maxsplit=1)
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + cert.encode()
        + b"\n-----END CERTIFICATE-----\n"
    )


class Runner(Script):
    COMMAND = "frankencert"
    LOGGER_NAME = "frankenrunner"

    def __init__(self, parser: ArgumentParser, config: ConfigType) -> None:
        super().__init__(parser, config)
        self.db: DBHandler

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--plugin-path",
            type=Path,
            metavar="PATH",
            help="path to executables used as loaders",
            default=self.get_config_value("frankencert.plugin_path", None),
        )
        self.parser.add_argument(
            "--db",
            type=Path,
            help="path to sqlite database",
            default=self.get_config_value("frankencert.db_path", None),
        )

    def load_ipc_plugins(self, path: Path) -> list[BasePlugin]:
        out: list[BasePlugin] = []
        for loader in path.iterdir():
            if loader.is_dir():
                continue
            s = loader.stat()
            if s.st_mode & 0o100 or s.st_mode & 0o010 or s.st_mode & 0o001:
                out.append(IPCPlugin(loader))
        return out

    def process_tests(self, args: Namespace) -> None:
        self.db.run_add(sys.argv, datetime.now())

        plugins: list[BasePlugin] = [
            GNUTLS_Plugin(),
            PythonPlugin(),
        ]

        if (p := args.plugin_path) is not None:
            plugins += self.load_ipc_plugins(p)

        self.logger.info(f"loaded plugins: {plugins}")

        for i, line in enumerate(sys.stdin):
            if i % 1000 == 0:
                self.logger.info(f"parsing cert #{i}")
            cert = parse_line(line)

            for plugin in plugins:
                self.logger.trace(f"running plugin {plugin}")
                start_time = datetime.now()
                res = plugin.run(cert)
                end_time = datetime.now()

                # Do not log successfully parsed runs.
                if res is None:
                    continue

                self.logger.info(f"{plugin}: error: {res}")
                in_data = {"in": cert.decode()}
                out_data = {"out": res}

                self.db.result_add(
                    loader=str(plugin),
                    in_data=in_data,
                    out_data=out_data,
                    start_time=start_time,
                    end_time=end_time,
                )

    def main(self, args: Namespace) -> None:
        self.db = DBHandler.connect(args.db)
        self.process_tests(args)

    def entry_point(self, args: Namespace) -> int:
        exit_code = 0

        try:
            exit_code = super().entry_point(args)
        except Exception as e:
            self.logger.exception(f"exception occured: {e}")
            exit_code = 1
        finally:
            self.db.run_finish(datetime.now(), exit_code)
            self.db.commit()
            self.db.close()

        return exit_code


def main() -> None:
    config, _ = load_config_file()

    parser = argparse.ArgumentParser()
    runner = Runner(parser, config)
    sys.exit(runner.entry_point(parser.parse_args()))


if __name__ == "__main__":
    main()
