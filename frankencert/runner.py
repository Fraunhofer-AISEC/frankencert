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
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import cryptography
import mbedtls
import OpenSSL.version
from cryptography.utils import CryptographyDeprecationWarning
from gallia.command import Script
from gallia.config import Config, load_config_file
from mbedtls.x509 import CRT as MBEDCertificate
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate as openssl_load_cert

from frankencert.asn1 import parse_asn1_json

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from cryptography import x509  # noqa

SCHEMA = """
CREATE TABLE scan_run (
    id INTEGER PRIMARY KEY,
    command TEXT check(json_valid(command)),
    start_time REAL NOT NULL,
    end_time REAL,
    exit_code INTEGER
) STRICT;

CREATE TABLE plugin (
    id INTEGER PRIMARY KEY,
    name TEXT,
    description TEXT,
    version TEXT
) STRICT;

CREATE TABLE stdin (
    id INTEGER PRIMARY KEY,
    asn1_tree TEXT check(json_valid(asn1_tree)),
    zlint_result TEXT check(json_valid(zlint_result)),
    data BLOB
) STRICT;

CREATE TABLE scan_result (
    id INTEGER PRIMARY KEY,
    run INTEGER NOT NULL REFERENCES scan_run(id) ON UPDATE CASCADE ON DELETE CASCADE,
    loader TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL NOT NULL,
    success INTEGER,
    stdin_id INTEGER REFERENCES stdin(id) ON UPDATE CASCADE ON DELETE CASCADE,
    stdout BLOB,
    stderr BLOB
) STRICT;

CREATE INDEX success_index ON scan_result(run, success);
CREATE INDEX loader_index ON scan_result(run, loader);
"""


def zlint(cert: bytes) -> str:
    p = subprocess.run(["zlint"], input=cert, capture_output=True, check=True)
    return p.stdout.decode()


class BasePlugin(ABC):
    def __str__(self) -> str:
        return self.__class__.__name__

    def __repr__(self) -> str:
        return str(self)

    @abstractmethod
    def run(self, cert: bytes) -> dict[str, Any]:
        ...

    @property
    def name(self) -> str:
        return repr(self)

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        ...


class SubprocessPlugin(BasePlugin):
    COMMAND: list[str] = []
    VERSION_COMMAND: list[str] = []

    def __init__(
        self,
        command: list[str] | None = None,
        version_command: list[str] | None = None,
    ) -> None:
        self.command = self.COMMAND if command is None else command
        self.version_command = (
            self.VERSION_COMMAND if version_command is None else version_command
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.command})"

    def run(self, cert: bytes) -> dict[str, Any]:
        p = subprocess.run(
            self.command,
            input=cert,
            capture_output=True,
        )

        if p.returncode != 0:
            return {
                "stderr": p.stderr,
                "stdout": p.stdout,
                "exitcode": p.returncode,
            }
        return {}

    @property
    def description(self) -> str:
        return f"calls {self.command} as a subprocess"

    @property
    def version(self) -> str:
        p = subprocess.run(
            self.version_command,
            capture_output=True,
            check=True,
        )
        return p.stdout.decode()


class GoPlugin(SubprocessPlugin):
    def __init__(
        self,
        command: list[str],
        version: str,
    ) -> None:
        self._version = version
        super().__init__(command)

    @property
    def version(self) -> str:
        return self._version


class GNUTLS_Plugin(SubprocessPlugin):
    COMMAND = [
        "certtool",
        "--certificate-info",
        "--load-certificate",
        "/dev/stdin",
    ]
    VERSION_COMMAND = [
        "certtool",
        "--version",
    ]


class MBED_TLS_Plugin(BasePlugin):
    def run(self, cert: bytes) -> dict[str, Any]:
        out = {}
        try:
            MBEDCertificate.from_PEM(cert.decode())
        except Exception as e:
            out["stderr"] = str(e)

        return out

    @property
    def version(self) -> str:
        return mbedtls.version.version

    @property
    def description(self) -> str:
        return "mbedtls via a wrapper python library in process"


class OpenSSL_Plugin(BasePlugin):
    def run(self, cert: bytes) -> dict[str, Any]:
        out = {}
        try:
            openssl_load_cert(FILETYPE_PEM, cert)
        except Exception as e:
            out["stderr"] = str(e)

        return out

    @property
    def description(self) -> str:
        return OpenSSL.version.__summary__

    @property
    def version(self) -> str:
        return OpenSSL.version.__version__


class PythonPlugin(BasePlugin):
    def run(self, cert: bytes) -> dict[str, Any]:
        out = {}
        try:
            x509.load_pem_x509_certificate(cert)
        except Exception as e:
            out["stderr"] = str(e)

        return out

    @property
    def description(self) -> str:
        return "python cryptography package"

    @property
    def version(self) -> str:
        return cryptography.__version__


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
            db.commit()

        return cls(path, db, cur)

    def add_plugin(self, name: str, description: str, version: str) -> None:
        self.cur.execute(
            """INSERT INTO plugin(name, description, version) VALUES(?, ?, ?)""",
            (name, description, version),
        )

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

    def stdin_add(self, data: bytes) -> int:
        self.cur.execute(
            "INSERT INTO stdin(data) VALUES(?)",
            (data,),
        )
        assert self.cur.lastrowid
        return self.cur.lastrowid

    def get_certs(self) -> Iterator[tuple[int, bytes]]:
        cur = self.cur.execute(
            "SELECT id, data from stdin",
        )
        for row in cur.fetchall():
            yield (row[0], row[1])

    def zlint_result_add(self, cert_id: int, cert: bytes) -> None:
        try:
            zlint_result = json.dumps({"result": json.loads(zlint(cert)), "success": True})
        except subprocess.SubprocessError as e:
            zlint_result = json.dumps({"result": str(e), "success": False})

        self.cur.execute(
            """UPDATE stdin SET zlint_result=? WHERE id==?""", (zlint_result, cert_id)
        )

    def asn1_tree_add(self, cert_id: int, cert: bytes) -> None:
        try:
            asn1_tree = json.dumps(
                {"result": json.loads(parse_asn1_json(cert.decode())), "success": True}
            )
        except Exception as e:
            asn1_tree = json.dumps({"result": str(e), "success": False})

        self.cur.execute(
            """UPDATE stdin SET asn1_tree=? WHERE id==?""", (asn1_tree, cert_id)
        )

    def result_add(
        self,
        loader: str,
        start_time: datetime,
        end_time: datetime,
        success: bool,
        stdin_id: int,
        stdout: bytes | None,
        stderr: bytes | None,
    ) -> int:
        assert self.run_id, "run_id is not set"
        self.cur.execute(
            """INSERT INTO scan_result(
                    run,
                    loader,
                    start_time,
                    end_time,
                    success,
                    stdin_id,
                    stdout,
                    stderr
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.run_id,
                loader,
                start_time.timestamp(),
                end_time.timestamp(),
                success,
                stdin_id,
                stdout,
                stderr,
            ),
        )
        assert self.cur.lastrowid
        return self.cur.lastrowid

    def purge_unrefed_certs(self) -> None:
        cur = self.cur.execute(
            """
            SELECT stdin.id 
                FROM stdin 
                LEFT JOIN scan_result
                ON stdin.id = scan_result.stdin_id
                WHERE scan_result.stdin_id IS NULL"""
        )

        for row in cur.fetchall():
            row_id = row[0]
            self.cur.execute(f"DELETE FROM stdin WHERE stdin.id = {row_id}")


def parse_line(line: str, as_json: bool) -> bytes:
    if as_json:
        data = json.loads(line)
        return cast(bytes, data["cert"].encode())

    _, cert = line.split(",", maxsplit=1)
    out = (
        b"-----BEGIN CERTIFICATE-----\n"
        + cert.encode().strip()
        + b"\n-----END CERTIFICATE-----\n"
    )
    return out.strip()


class Runner(Script):
    COMMAND = "frankencert"
    LOGGER_NAME = "frankenrunner"

    def __init__(self, parser: ArgumentParser, config: Config) -> None:
        super().__init__(parser, config)
        self.db: DBHandler

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--db",
            type=Path,
            help="path to sqlite database",
            default=self.config.get_value("frankencert.db_path", None),
        )
        self.parser.add_argument(
            "-i",
            "--indices",
            type=int,
            nargs="+",
            help="indices of plugins to run only",
        )
        self.parser.add_argument(
            "--start",
            type=int,
            help="start reading at this offset",
        )
        self.parser.add_argument(
            "--stop",
            type=int,
            help="stop reading at this offset",
        )
        self.parser.add_argument(
            "-j",
            "--json",
            action="store_true",
            help="read from stdin as json",
        )

    def _process_plugin(
        self,
        plugin: BasePlugin,
        cert: bytes,
        stdin_id: int,
    ) -> dict[str, Any]:
        self.logger.trace(f"running plugin {plugin}")

        # Do not log successfully parsed runs.
        out = {
            "start_time": datetime.now(),
            "plugin": repr(plugin),
        }
        res = plugin.run(cert)
        out["end_time"] = datetime.now()

        if res != {}:
            out["stdin_id"] = stdin_id
            out["res"] = res
        else:
            out["stdin_id"] = None
            out["res"] = None

        return out

    def _flush_futures(self, futures: list[Future[dict[str, Any]]]) -> None:
        for future in as_completed(futures):
            res = future.result()

            success = True
            if res["stdin_id"] is not None:
                self.logger.info(f"{res['plugin']}: {res['res']}")
                success = False

            # We only want failed certs in the database.
            if success is True:
                continue

            if (r := res["res"]) is not None:
                stdout = (
                    r["stdout"] if "stdout" in r and r["stdout"] is not None else None
                )
                stderr = (
                    r["stderr"] if "stderr" in r and r["stderr"] is not None else None
                )
            else:
                stdout = None
                stderr = None

            self.db.result_add(
                loader=res["plugin"],
                start_time=res["start_time"],
                end_time=res["end_time"],
                success=success,
                stdin_id=res["stdin_id"],
                stderr=stderr.encode() if isinstance(stderr, str) else stderr,
                stdout=stdout.encode() if isinstance(stdout, str) else stdout,
            )

        self.db.purge_unrefed_certs()
        self.db.commit()

    def _lint_certs(self) -> None:
        for id, cert in self.db.get_certs():
            self.db.asn1_tree_add(id, cert)
            self.db.zlint_result_add(id, cert)

    def main(self, args: Namespace) -> None:
        self.db = DBHandler.connect(args.db)
        self.db.run_add(sys.argv, datetime.now())

        plugins: list[BasePlugin] = [
            GNUTLS_Plugin(),
            MBED_TLS_Plugin(),
            OpenSSL_Plugin(),
            PythonPlugin(),
            GoPlugin(["loaders/go/loader"], "1.19.1"),
            GoPlugin(["loaders/go/go1.16.15-loader"], "1.16.15"),
            GoPlugin(["loaders/go/go1.17.13-loader"], "1.17.13"),
            GoPlugin(["loaders/go/go1.18.6-loader"], "1.18.6"),
            GoPlugin(["loaders/go/go1.19.1-loader"], "1.19.1"),
        ]

        for plugin in plugins:
            self.db.add_plugin(str(plugin), plugin.description, plugin.version)

        self.logger.info(f"loaded plugins: {plugins}")

        with ThreadPoolExecutor() as executor:
            futures = []

            for i, line in enumerate(sys.stdin):
                n = i + 1
                if n % 1000 == 0:
                    self.logger.info(f"parsing cert #{n}")

                cert = parse_line(line, args.json)

                stdin_id = self.db.stdin_add(cert)

                for j, plugin in enumerate(plugins):
                    if args.indices is not None and j in args.indices:
                        continue

                    fut = executor.submit(
                        self._process_plugin,
                        plugin,
                        cert,
                        stdin_id,
                    )
                    futures.append(fut)

                if len(futures) % 1000 == 0:
                    self._flush_futures(futures)
                    futures = []

            self._flush_futures(futures)
            self._lint_certs()

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
