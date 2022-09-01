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
from subprocess import PIPE, Popen
from tempfile import NamedTemporaryFile
from typing import Any

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


class MBED_TLS_Plugin(BasePlugin):
    def run(self, cert: bytes) -> None | str:
        with NamedTemporaryFile() as f:
            f.write(cert)
            f.seek(0)

            p = subprocess.run(
                [
                    "mbedtls_cert_app",
                    "mode=file",
                    f"filename={f.name}",
                ],
                input=cert,
                capture_output=True,
            )
        if p.returncode != 0:
            return p.stdout.decode().strip()
        return None


class OpenSSL_Plugin(BasePlugin):
    def run(self, cert: bytes) -> None | str:
        p = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                "/dev/stdin",
                "-noout",
                "-text",
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
        self.parser.add_argument(
            "-i",
            "--indices",
            type=int,
            nargs="+",
            help="indices of plugins to run only",
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

    def _process_plugin(self, plugin: BasePlugin, cert: bytes) -> dict[str, Any]:
        self.logger.trace(f"running plugin {plugin}")

        # Do not log successfully parsed runs.
        out = {"start_time": datetime.now(), "plugin": str(plugin), "log_it": False}
        res = plugin.run(cert)
        out["end_time"] = datetime.now()

        if res is not None:
            out["in_data"] = {"in": cert.decode()}
            out["out_data"] = {"out": res}
            out["log_it"] = True

        return out

    def _flush_futures(self, futures: list[Future[dict[str, Any]]]) -> None:
        for future in as_completed(futures):
            res = future.result()

            if not res["log_it"]:
                continue

            self.logger.info(f"{res['plugin']}: {res['out_data']['out']}")

            self.db.result_add(
                loader=res["plugin"],
                in_data=res["in_data"],
                out_data=res["out_data"],
                start_time=res["start_time"],
                end_time=res["end_time"],
            )

    def process_tests(self, args: Namespace) -> None:
        self.db.run_add(sys.argv, datetime.now())

        plugins: list[BasePlugin] = [
            GNUTLS_Plugin(),
            MBED_TLS_Plugin(),
            OpenSSL_Plugin(),
            PythonPlugin(),
        ]

        if (p := args.plugin_path) is not None:
            plugins += self.load_ipc_plugins(p)

        self.logger.info(f"loaded plugins: {plugins}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []

            for i, line in enumerate(sys.stdin):
                if i % 1000 == 0:
                    self.logger.info(f"parsing cert #{i}")

                cert = parse_line(line)

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
