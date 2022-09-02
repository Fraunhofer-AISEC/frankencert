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
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

from cryptography.utils import CryptographyDeprecationWarning
from gallia.command import Script
from gallia.config import ConfigType, load_config_file

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
    success int,
    in_data text check(json_valid(in_data)),
    out_data text check(json_valid(out_data))
) STRICT;
"""


class BasePlugin(ABC):
    def __str__(self) -> str:
        return self.__class__.__name__

    def __repr__(self) -> str:
        return str(self)

    @abstractmethod
    def run(self, cert: bytes) -> dict[str, Any]:
        ...


class SubprocessPlugin(BasePlugin):
    COMMAND: list[str] = []

    def __init__(self, command: list[str] | None = None) -> None:
        self.command = self.COMMAND if command is None else command

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.command})"

    def run(self, cert: bytes) -> dict[str, Any]:
        out = {}
        p = subprocess.run(
            self.command,
            input=cert,
            capture_output=True,
        )

        if p.returncode != 0:
            out["stderr"] = p.stderr.decode().strip()
            out["stdout"] = p.stdout.decode().strip()

        return out


class GoPlugin(SubprocessPlugin):
    pass


class GNUTLS_Plugin(SubprocessPlugin):
    COMMAND = [
        "certtool",
        "--certificate-info",
        "--load-certificate",
        "/dev/stdin",
    ]


class MBED_TLS_Plugin(SubprocessPlugin):
    def run(self, cert: bytes) -> dict[str, Any]:
        with NamedTemporaryFile() as f:
            f.write(cert)
            f.seek(0)

            self.command = [
                "mbedtls_cert_app",
                "mode=file",
                f"filename={f.name}",
            ]

            return super().run(cert)


class OpenSSL_Plugin(SubprocessPlugin):
    COMMAND = [
        "openssl",
        "x509",
        "-in",
        "/dev/stdin",
        "-noout",
        "-text",
    ]


class PythonPlugin(BasePlugin):
    def run(self, cert: bytes) -> dict[str, Any]:
        out = {}
        try:
            x509.load_pem_x509_certificate(cert)
        except Exception as e:
            out["stderr"] = str(e)

        return out


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
        success: bool,
        in_data: dict[str, str],
        out_data: dict[str, str],
    ) -> int:
        assert self.run_id, "run_id is not set"
        self.cur.execute(
            """INSERT INTO scan_result(
                    run,
                    loader,
                    start_time,
                    end_time,
                    success,
                    in_data,
                    out_data
                ) VALUES(?, ?, ?, ?, ?, ?, ?)""",
            (
                self.run_id,
                loader,
                start_time.timestamp(),
                end_time.timestamp(),
                success,
                json.dumps(in_data),
                json.dumps(out_data),
            ),
        )
        assert self.cur.lastrowid
        return self.cur.lastrowid


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

    def __init__(self, parser: ArgumentParser, config: ConfigType) -> None:
        super().__init__(parser, config)
        self.db: DBHandler

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--db",
            type=Path,
            help="path to sqlite database",
            default=self.get_config_value("frankencert.db_path", None),
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

    def _process_plugin(self, plugin: BasePlugin, cert: bytes) -> dict[str, Any]:
        self.logger.trace(f"running plugin {plugin}")

        # Do not log successfully parsed runs.
        out = {"start_time": datetime.now(), "plugin": str(plugin), "log_it": False}
        res = plugin.run(cert)
        out["end_time"] = datetime.now()

        if res != {}:
            out["in_data"] = {"in": {"stdin": cert.decode()}}
            out["out_data"] = {"out": res}
        else:
            out["in_data"] = {"in": None}
            out["out_data"] = {"out": None}

        return out

    def _flush_futures(self, futures: list[Future[dict[str, Any]]]) -> None:
        for future in as_completed(futures):
            res = future.result()

            success = True
            if res["in_data"]["in"] is not None:
                self.logger.info(f"{res['plugin']}: {res['out_data']}")
                success = False

            self.db.result_add(
                loader=res["plugin"],
                in_data=res["in_data"],
                out_data=res["out_data"],
                start_time=res["start_time"],
                end_time=res["end_time"],
                success=success,
            )
        self.db.commit()

    def main(self, args: Namespace) -> None:
        self.db = DBHandler.connect(args.db)
        self.db.run_add(sys.argv, datetime.now())

        plugins: list[BasePlugin] = [
            GNUTLS_Plugin(),
            MBED_TLS_Plugin(),
            OpenSSL_Plugin(),
            PythonPlugin(),
            GoPlugin(["loaders/go/loader"]),
        ]

        self.logger.info(f"loaded plugins: {plugins}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []

            for i, line in enumerate(sys.stdin):
                n = i + 1
                if n % 1000 == 0:
                    self.logger.info(f"parsing cert #{n}")

                cert = parse_line(line, args.json)

                for i, plugin in enumerate(plugins):
                    if args.indices is not None and i in args.indices:
                        continue

                    fut = executor.submit(self._process_plugin, plugin, cert)
                    futures.append(fut)

                if len(futures) % 1000 == 0:
                    self._flush_futures(futures)
                    futures = []

            self._flush_futures(futures)
            futures = []

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
