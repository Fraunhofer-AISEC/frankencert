import argparse
import functools
import json
from enum import IntEnum, auto, unique
from functools import cache
from typing import Any, TypedDict

import polars as pl


@unique
class ErrorClass(IntEnum):
    PARSE_ERROR = auto()
    INVALID_VALUE = auto()
    CRYPTO_ERROR = auto()
    URL_ERROR = auto()
    UNCATEGORIZED = auto()


def list_in_string(needles: list[str], haystack: str) -> bool:
    for needle in needles:
        if needle in haystack:
            return True
    return False


class RowType(TypedDict):
    stderr: str
    stdout: str
    loader: str


def _classify_go_116(row: RowType) -> ErrorClass:
    if list_in_string(["cannot parse", "failed to parse", "asn1:"], row["stderr"]):
        return ErrorClass.PARSE_ERROR
    elif list_in_string(["invalid", "out of range", "malformed"], row["stderr"]):
        return ErrorClass.INVALID_VALUE
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row["stderr"],
    ):
        return ErrorClass.CRYPTO_ERROR
    return ErrorClass.UNCATEGORIZED


def _classify_go_117(row: RowType) -> ErrorClass:
    if list_in_string(["cannot parse", "failed to parse"], row["stderr"]):
        return ErrorClass.PARSE_ERROR
    elif list_in_string(["invalid", "out of range", "malformed"], row["stderr"]):
        return ErrorClass.INVALID_VALUE
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row["stderr"],
    ):
        return ErrorClass.CRYPTO_ERROR
    return ErrorClass.UNCATEGORIZED


def _classify_go_118(row: RowType) -> ErrorClass:
    if list_in_string(["cannot parse", "failed to parse"], row["stderr"]):
        return ErrorClass.PARSE_ERROR
    elif "invalid" in row["stderr"]:
        return ErrorClass.INVALID_VALUE
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row["stderr"],
    ):
        return ErrorClass.CRYPTO_ERROR
    return ErrorClass.UNCATEGORIZED


def _classify_go_119(row: RowType) -> ErrorClass:
    if list_in_string(["invalid", "malformed"], row["stderr"]):
        return ErrorClass.INVALID_VALUE
    elif "out of range" in row["stderr"]:
        return ErrorClass.INVALID_VALUE
    elif list_in_string(["cannot parse", "failed to parse"], row["stderr"]):
        return ErrorClass.PARSE_ERROR
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row["stderr"],
    ):
        return ErrorClass.CRYPTO_ERROR
    else:
        return ErrorClass.UNCATEGORIZED


def _classify_go(row: RowType) -> ErrorClass:
    if row["stderr"].startswith("x509: cannot parse URI"):
        return ErrorClass.URL_ERROR
    elif list_in_string(["invalid", "malformed"], row["stderr"]):
        return ErrorClass.INVALID_VALUE
    elif "out of range" in row["stderr"]:
        return ErrorClass.INVALID_VALUE
    elif list_in_string(["cannot parse", "failed to parse"], row["stderr"]):
        return ErrorClass.PARSE_ERROR
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row["stderr"],
    ):
        return ErrorClass.CRYPTO_ERROR
    else:
        return ErrorClass.UNCATEGORIZED

def _classify_python(row: RowType) -> ErrorClass:
    if "InvalidValue" in row["stderr"]:
        return ErrorClass.INVALID_VALUE
    elif "not a valid X509 version" in row["stderr"]:
        return ErrorClass.INVALID_VALUE
    elif "ParseError" in row["stderr"]:
        return ErrorClass.PARSE_ERROR
    else:
        return ErrorClass.UNCATEGORIZED


def _classify_gnutls(row: RowType) -> ErrorClass:
    out = ErrorClass.UNCATEGORIZED

    if "ASN1 parser" in row["stderr"]:
        out = ErrorClass.PARSE_ERROR
    elif "Error in the time fields" in row["stderr"]:
        out = ErrorClass.INVALID_VALUE
    elif "Unknown Subject" in row["stderr"]:
        out = ErrorClass.INVALID_VALUE
    elif "Duplicate extension" in row["stderr"]:
        out = ErrorClass.INVALID_VALUE
    elif "time encoding is invalid" in row["stderr"]:
        out = ErrorClass.INVALID_VALUE
    elif "Error in the certificate" in row["stderr"]:
        out = ErrorClass.UNCATEGORIZED

    return out


def _mbedtls_get_error_code(s: str) -> int:
    substr = s.splitlines()[-1]
    substr = substr.rsplit(" ", 2)[-1]
    substr = substr.replace('"', "")
    try:
        return int(substr)
    except ValueError:
        substr = s[s.index("[") + 1 : s.index("]")]
        return int(substr, 0)


def _classify_mbeldtls(row: RowType) -> ErrorClass:
    match _mbedtls_get_error_code(row["stderr"]):
        case 0x2400 | 0x23E0 | 0x2562 | 0x2300 | 0x2580 | 0x2500 | 0x23E2:
            return ErrorClass.INVALID_VALUE
        case 0x2680 | 0x2080 | 0x3D00 | 0x3C80 | 0x3A00 | 0x262E | 0x3B00:
            return ErrorClass.CRYPTO_ERROR
        case 0x21E6 | 0x2566 | 0x2564:
            return ErrorClass.PARSE_ERROR
        case _:
            return ErrorClass.UNCATEGORIZED


def get_error_class(row: RowType) -> str | None:
    out = None
    loader = row["loader"]

    if loader.startswith("GoPlugin"):
        if "1.19" in loader:
            out = _classify_go_119(row).name
        elif "1.18" in loader:
            out = _classify_go_118(row).name
        elif "1.17" in loader:
            out = _classify_go_117(row).name
        elif "1.16" in loader:
            out = _classify_go_116(row).name
        else:
            out = _classify_go(row).name
        return out
    elif loader == "PythonPlugin":
        out = _classify_python(row).name
    elif loader.startswith("GNUTLS_Plugin"):
        out = _classify_gnutls(row).name
    elif loader == "MBED_TLS_Plugin":
        out = _classify_mbeldtls(row).name

    return out


class Database:
    def __init__(self, uri: str) -> None:
        self.uri = uri

    @cache
    def runs(self) -> pl.DataFrame:
        df = pl.read_database(
            """SELECT
                    id,
                    command,
                    start_time,
                    end_time,
                    end_time - start_time AS duration
               FROM scan_run""",
            self.uri,
        )
        df = df.with_columns(
            [
                pl.from_epoch(pl.col("end_time")),
                pl.from_epoch(pl.col("start_time")),
                (pl.col("duration") / 3600),
            ]
        )

        return df

    @cache
    def results(self, index: int) -> pl.DataFrame:
        df = pl.read_database(
            f"""SELECT
                    scan_result.id,
                    loader,
                    start_time,
                    end_time,
                    end_time - start_time AS duration,
                    stderr,
                    stdout,
                    stdin.data as stdin,
                    zlint_result,
                    asn1_tree
                FROM scan_result
                JOIN stdin
                ON scan_result.stdin_id = stdin.id
                WHERE scan_result.run_id = {index}
                AND scan_result.success = FALSE;
            """,
            self.uri,
        )

        df = df.with_columns(
            [
                pl.col("stderr").apply(
                    functools.partial(bytes.decode, errors="replace")
                ),
                pl.col("stdout").apply(
                    functools.partial(bytes.decode, errors="replace")
                ),
                pl.col("stdin").apply(
                    functools.partial(bytes.decode, errors="replace")
                ),
                pl.col("zlint_result").apply(json.loads),
                # pl.col("asn1_tree").apply(json.loads),
                pl.from_epoch(pl.col("end_time")),
                pl.from_epoch(pl.col("start_time")),
                (pl.col("duration") / 3600),
            ]
        )
        df = df.with_columns(
            [
                (
                    pl.struct(["loader", "stderr", "stdout"]).apply(get_error_class)
                ).alias("error_class"),
            ]
        )

        return df

    @cache
    def used_loaders(self, index: int) -> pl.DataFrame:
        df = pl.read_database(
            f"""SELECT DISTINCT
                    loader
                FROM scan_result
                    WHERE scan_result.run_id == {index};
                """,
            self.uri,
        )
        return df

    @cache
    def total_testruns(self, index: int) -> int:
        df = pl.read_database(
            f"""SELECT
                    COUNT(*) AS total_testruns
                FROM scan_result
                    WHERE scan_result.run_id == {index};
                """,
            self.uri,
        )
        return int(df["total_testruns"][0])

    @cache
    def run_duration(self, index: int) -> float:
        df = pl.read_database(
            f"""SELECT
                    end_time - start_time AS run_duration
                FROM scan_run where id == {index};
                """,
            self.uri,
        )
        return float(df["run_duration"][0])


def cmd_show_runs(args: argparse.Namespace, db: Database) -> None:
    df = db.runs()
    print(df.write_json(row_oriented=True))


def cmd_show_results(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)
    if args.loader is not None:
        df = df.filter(pl.col("loader") == args.loader)

    print(df.write_json(row_oriented=True))


def cmd_show_stats(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)

    errors_total = len(df)
    out = {
        "errors_total": errors_total,
        "error_ratio": errors_total / db.total_testruns(args.index),
        "run_duration": db.run_duration(args.index) / 3600,
        "total_testruns": db.total_testruns(args.index),
        "loaders": [],
    }

    for row in df.unique(subset=["loader"]).select(pl.col("loader")).rows():
        loader_name = row[0]
        loader = {"name": loader_name}

        df2 = df.filter(pl.col("loader") == loader_name)
        errors = len(df2)
        loader["errors_total"] = errors
        loader["duration_mean"] = df2.select(pl.col("duration")).mean().item()
        loader["error_classes"] = []

        error_classes_df = df2.groupby("error_class").agg(
            pl.count(),
        )
        print(error_classes_df)
        d = error_classes_df.to_dict(as_series=False)
        for i, k in enumerate(d["error_class"]):
            v = d["count"][i]
            loader["error_classes"].append(
                {
                    "name": k,
                    "errors_total": v,
                    "error_ratio": v / errors,
                }
            )
        out["loaders"].append(loader)  # type: ignore

    print(json.dumps(out))


def cmd_show_certs(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)

    out: dict[str, Any] = {}
    out["per_loader"] = {}
    for row in df.unique(subset=["loader"]).select(pl.col("loader")).iter_rows():
        loader_name = row[0]
        if loader_name not in out["per_loader"]:
            out["per_loader"][loader_name] = {}

        subdict = out["per_loader"][loader_name]
        df2 = df.filter(pl.col("loader") == loader_name)

        for err_row in (
            df2.unique(subset=["error_class"]).select(pl.col("error_class")).iter_rows()
        ):
            error_class = err_row[0]
            if error_class not in subdict:
                subdict[error_class] = {}

            subdict = subdict[error_class]
            subdict["cert"] = [
                x[0]
                for x in df2.filter(pl.col("error_class") == error_class)
                .select(pl.col("stdin"))
                .rows()
            ]

    print(json.dumps(out))


def cmd_show_loaders(args: argparse.Namespace, db: Database) -> None:
    df = db.used_loaders(args.index)
    print(df.write_json(row_oriented=True))


def cmd_show_errors(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)

    out: dict[str, Any] = {}
    out["per_loader"] = {}
    for row in df.unique(subset=["loader"]).iter_rows(named=True):
        loader_name = row["loader"]
        if loader_name not in out["per_loader"]:
            out["per_loader"][loader_name] = {}

        out["per_loader"][loader_name]["error_class"] = {}
        for err_row in df.unique(subset=["error_class"]).iter_rows(named=True):
            error_class = err_row["error_class"]
            if args.uncategorized and error_class != ErrorClass.UNCATEGORIZED.name:
                continue

            if error_class not in out["per_loader"][loader_name]["error_class"]:
                out["per_loader"][loader_name]["error_class"][error_class] = {}

            df2 = df.filter(
                (pl.col("loader") == loader_name)
                & (pl.col("error_class") == error_class)
            )
            subdict = out["per_loader"][loader_name]["error_class"][error_class]
            subdict["stderr"] = df2.unique(subset=["stderr"])["stderr"].to_list()
            subdict["stdout"] = df2.unique(subset=["stdout"])["stdout"].to_list()

    print(json.dumps(out))


def cmd_show_overlap(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)
    df = df.with_columns([pl.col("stdin").rank(method="dense").alias("cert_id")])

    group = df.groupby("cert_id")

    print(f"failed unique certs: {len(group.all())}")

    print(
        group.agg(
            [
                pl.col("stdin"),
                pl.col("loader"),
                pl.col("loader").count().alias("n_loaders"),
            ]
        ).filter(pl.col("n_loaders") > 1)
    )


# certs anschaun, die bei mehr als einem loader gefailed sind und gruppe vergleichen


def parse_args() -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser.add_argument("--db", required=True, help="path to sqlite db")

    runs_parser = subparsers.add_parser("runs", help="show testruns")
    runs_parser.set_defaults(cmd="runs")

    results_parser = subparsers.add_parser("results", help="show testruns")
    results_parser.add_argument(
        "--loader",
        help="specify the relevant loader",
    )
    results_parser.add_argument("index")
    results_parser.set_defaults(cmd="results")

    stats_parser = subparsers.add_parser("stats", help="show stats for testruns")
    stats_parser.add_argument("index")
    stats_parser.set_defaults(cmd="stats")

    certs_parser = subparsers.add_parser("certs", help="show error groups")
    certs_parser.add_argument("index")
    certs_parser.set_defaults(cmd="certs")

    loaders_parser = subparsers.add_parser("loaders", help="show error groups")
    loaders_parser.add_argument("index")
    loaders_parser.set_defaults(cmd="loaders")

    errors_parser = subparsers.add_parser("errors", help="show error groups")
    errors_parser.add_argument("index")
    errors_parser.add_argument(
        "-u",
        "--uncategorized",
        action="store_true",
        help="only show uncategorized",
    )
    errors_parser.set_defaults(cmd="errors")

    overlap_parser = subparsers.add_parser("overlap", help="show error groups")
    overlap_parser.add_argument("index")
    overlap_parser.set_defaults(cmd="overlap")

    return parser.parse_args(), parser


def main() -> None:
    args, parser = parse_args()
    db = Database(args.db)

    if "cmd" in args:
        match args.cmd:
            case "runs":
                cmd_show_runs(args, db)
            case "results":
                cmd_show_results(args, db)
            case "stats":
                cmd_show_stats(args, db)
            case "certs":
                cmd_show_certs(args, db)
            case "loaders":
                cmd_show_loaders(args, db)
            case "errors":
                cmd_show_errors(args, db)
            case "overlap":
                cmd_show_overlap(args, db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
