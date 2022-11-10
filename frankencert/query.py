import argparse
import json
from datetime import datetime
from enum import IntEnum, auto, unique
from functools import cache

import pandas as pd
from sqlalchemy import create_engine  # type: ignore


@unique
class ErrorClass(IntEnum):
    PARSE_ERROR = auto()
    INVALID_VALUE = auto()
    CRYPTO_ERROR = auto()
    UNCATEGORIZED = auto()


def list_in_string(needles: list[str], haystack: str) -> bool:
    for needle in needles:
        if needle in haystack:
            return True
    return False


def _classify_go_116(row):
    if list_in_string(["cannot parse", "failed to parse", "asn1:"], row.stderr):
        return ErrorClass.PARSE_ERROR.name
    elif list_in_string(["invalid", "out of range", "malformed"], row.stderr):
        return ErrorClass.INVALID_VALUE.name
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row.stderr,
    ):
        return ErrorClass.CRYPTO_ERROR.name
    return ErrorClass.UNCATEGORIZED.name


def _classify_go_117(row):
    if list_in_string(["cannot parse", "failed to parse"], row.stderr):
        return ErrorClass.PARSE_ERROR.name
    elif list_in_string(["invalid", "out of range", "malformed"], row.stderr):
        return ErrorClass.INVALID_VALUE.name
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row.stderr,
    ):
        return ErrorClass.CRYPTO_ERROR.name
    return ErrorClass.UNCATEGORIZED.name


def _classify_go_118(row):
    if list_in_string(["cannot parse", "failed to parse"], row.stderr):
        return ErrorClass.PARSE_ERROR.name
    elif "invalid" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row.stderr,
    ):
        return ErrorClass.CRYPTO_ERROR.name
    return ErrorClass.UNCATEGORIZED.name


def _classify_go_119(row):
    if list_in_string(["invalid", "malformed"], row.stderr):
        return ErrorClass.INVALID_VALUE.name
    elif "out of range" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif list_in_string(["cannot parse", "failed to parse"], row.stderr):
        return ErrorClass.PARSE_ERROR.name
    elif list_in_string(
        [
            "elliptic curve",
            "RSA key",
            "RSA modulus",
            "signature algorithm",
            "curve point",
        ],
        row.stderr,
    ):
        return ErrorClass.CRYPTO_ERROR.name
    else:
        return ErrorClass.UNCATEGORIZED.name


def _classify_go(row):
    return _classify_go_119(row)


def _classify_python(row):
    if "InvalidValue" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "not a valid X509 version" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "ParseError" in row.stderr:
        return ErrorClass.PARSE_ERROR.name
    else:
        return ErrorClass.UNCATEGORIZED.name


def _classify_gnutls(row):
    if "ASN1 parser" in row.stderr:
        return ErrorClass.PARSE_ERROR.name
    elif "Error in the time fields" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "Unknown Subject" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "Duplicate extension" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "time encoding is invalid" in row.stderr:
        return ErrorClass.INVALID_VALUE.name
    elif "Error in the certificate" in row.stderr:
        return ErrorClass.UNCATEGORIZED.name
    else:
        return ErrorClass.UNCATEGORIZED.name


def _mbedtls_get_error_code(s: str) -> int:
    substr = s.splitlines()[-1]
    substr = substr.rsplit(" ", 2)[-1]
    substr = substr.replace('"', "")
    try:
        return int(substr)
    except ValueError:
        substr = s[s.index("[") + 1 : s.index("]")]
        return int(substr, 0)


def _classify_mbeldtls(row) -> str:
    match _mbedtls_get_error_code(row.stderr):
        case 0x2400 | 0x23E0 | 0x2562 | 0x2300 | 0x2580 | 0x2500 | 0x23E2:
            return ErrorClass.INVALID_VALUE.name
        case 0x2680 | 0x2080 | 0x3D00 | 0x3C80 | 0x3A00 | 0x262E | 0x3B00:
            return ErrorClass.CRYPTO_ERROR.name
        case 0x21E6 | 0x2566 | 0x2564:
            return ErrorClass.PARSE_ERROR
        case _:
            return ErrorClass.UNCATEGORIZED.name


def get_error_class(row):
    if (l := row.loader).startswith("GoPlugin"):
        if "1.19" in l:
            return _classify_go_119(row)
        elif "1.18" in l:
            return _classify_go_118(row)
        elif "1.17" in l:
            return _classify_go_117(row)
        elif "1.16" in l:
            return _classify_go_116(row)
        else:
            return _classify_go(row)
    elif row.loader == "PythonPlugin":
        return _classify_python(row)
    elif row.loader == "GNUTLS_Plugin":
        return _classify_gnutls(row)
    elif row.loader == "MBED_TLS_Plugin":
        return _classify_mbeldtls(row)
    return None


class Database:
    def __init__(self, path_uri: str) -> None:
        self.engine = create_engine(path_uri)

    @cache
    def runs(self) -> pd.DataFrame:
        with self.engine.connect() as conn, conn.begin():
            df = pd.read_sql_query("SELECT * FROM scan_run", conn)

        df.start_time = df.start_time.apply(datetime.fromtimestamp)
        df.end_time = df.end_time.apply(datetime.fromtimestamp)
        df["duration"] = df.end_time - df.start_time

        return df

    @cache
    def results(self, index: int) -> pd.DataFrame:
        with self.engine.connect() as conn, conn.begin():
            df = pd.read_sql_query(
                f"""SELECT
                        id,
                        loader,
                        start_time,
                        end_time,
                        end_time - start_time AS duration,
                        in_data -> "$.in.stdin" AS stdin,
                        out_data -> "$.out.stderr" AS stderr,
                        out_data -> "$.out.stdout" AS stdout
                    FROM scan_result
                        WHERE scan_result.run == {index}
                        AND scan_result.success == FALSE;
                """,
                conn,
            )
        df.start_time = df.start_time.apply(datetime.fromtimestamp)
        df.end_time = df.end_time.apply(datetime.fromtimestamp)
        df["error_class"] = df.apply(get_error_class, axis=1)

        return df

    @cache
    def used_loaders(self, index: int) -> pd.DataFrame:
        with self.engine.connect() as conn, conn.begin():
            df = pd.read_sql_query(
                f"""SELECT DISTINCT
                        loader
                    FROM scan_result
                        WHERE scan_result.run == {index};
                """,
                conn,
            )
        return df

    @cache
    def total_testruns(self, index: int) -> int:
        with self.engine.connect() as conn, conn.begin():
            df = pd.read_sql_query(
                f"""SELECT
                        COUNT(*) AS total_testruns
                    FROM scan_result
                    WHERE scan_result.run == {index};
                """,
                conn,
            )
            return int(df.total_testruns[0])

    @cache
    def run_duration(self, index: int) -> float:
        with self.engine.connect() as conn, conn.begin():
            df = pd.read_sql_query(
                f"""SELECT
                        end_time - start_time AS run_duration
                    FROM scan_run where id == {index};
                """,
                conn,
            )
            return float(df.run_duration)


def cmd_show_runs(args: argparse.Namespace, db: Database) -> None:
    df = db.runs()
    print(df.to_json(orient="records", lines=True))


def cmd_show_results(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)
    if args.loader is not None:
        df = df[df.loader == args.loader]

    print(df.to_json(orient="records", lines=True))


def cmd_show_stats(args: argparse.Namespace, db: Database) -> None:
    df = db.results(args.index)

    errors_total = int(df.id.count())
    out = {
        "errors_total": errors_total,
        "error_ratio": errors_total / db.total_testruns(args.index),
        "run_duration": db.run_duration(args.index),
        "total_testruns": db.total_testruns(args.index),
        "loaders": [],
    }

    for loader_name in df.loader.unique():
        loader = {
            "name": loader_name,
        }

        df2 = df[df.loader == loader_name]
        errors = int(df2.loader.count())
        loader["errors_total"] = errors
        loader["duration_mean"] = float(df2.duration.mean())

        error_classes_df = df2.groupby("error_class").error_class.count()
        loader["error_classes"] = []
        for k, v in error_classes_df.astype(int).to_dict().items():
            loader["error_classes"].append(
                {
                    "name": k,
                    "errors_total": v,
                    "error_ratio": v / errors,
                }
            )
        out["loaders"].append(loader)

    print(json.dumps(out))


def cmd_show_certs(args: argparse.Namespace, db: Database):
    df = db.results(args.index)

    out = {}
    out["per_loader"] = {}
    for loader in df.loader.unique():
        if loader not in out["per_loader"]:
            out["per_loader"][loader] = {}

        subdict = out["per_loader"][loader]
        df2 = df[df.loader == loader]

        for error_class in df2.error_class.unique():
            if error_class not in subdict:
                subdict[error_class] = {}

            subdict = subdict[error_class]

            df3 = df2[df2.error_class == error_class]
            subdict["cert"] = list(df3.stdin)

    print(json.dumps(out))


def cmd_show_loaders(args: argparse.Namespace, db: Database):
    df = db.used_loaders(args.index)
    print(df.to_json(orient="records", lines=True))


def cmd_show_errors(args: argparse.Namespace, db: Database):
    df = db.results(args.index)

    out = {}
    out["per_loader"] = {}
    for loader in df.loader.unique():
        if loader not in out["per_loader"]:
            out["per_loader"][loader] = {}

        out["per_loader"][loader]["error_class"] = {}
        for error_class in df.error_class.unique():
            if args.uncategorized and error_class != ErrorClass.UNCATEGORIZED.name:
                continue

            if error_class not in out["per_loader"][loader]["error_class"]:
                out["per_loader"][loader]["error_class"][error_class] = {}

            df2 = df[df.loader == loader]
            df3 = df2[df2.error_class == error_class]
            subdict = out["per_loader"][loader]["error_class"][error_class]
            subdict["stderr"] = list(df3.stderr.unique())
            subdict["stdout"] = list(df3.stdout.unique())

    print(json.dumps(out))


def cmd_show_overlap(args: argparse.Namespace, db: Database):
    df = db.results(args.index)

    df["cert_id"] = df.stdin.rank(method="dense", ascending=False).astype(int)

    df = df[["cert_id", "loader"]]
    df = pd.DataFrame(df.groupby("cert_id").loader.apply(list))

    print(f"failed unique certs: {len(df)}")

    df["loader_count"] = df.loader.apply(len)

    overlap_df = df[df.loader_count > 1]
    foo = df[df.loader_count == 1]
    foo["loader"] = foo.loader.apply(lambda x: x[0])
    print(foo.groupby("loader").agg("count"))
    print(f"failed in multiple loaders: {len(overlap_df)}")


# certs anschaun, die bei mehr als einem loader gefailed sind und gruppe vergleichen


def parse_args() -> argparse.Namespace:
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

    return parser.parse_args()


def main() -> None:
    args = parse_args()
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


if __name__ == "__main__":
    main()
