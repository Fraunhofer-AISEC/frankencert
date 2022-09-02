import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path


def cmd_show_runs(args: argparse.Namespace, cursor: sqlite3.Cursor) -> None:
    res = cursor.execute(
        """
        SELECT * FROM scan_run;
    """
    )
    for line in res:
        id_, command, start_time_ts, end_time_ts, exit_code = line

        out = {
            "id": id_,
            "command": command,
            "exit_code": exit_code,
        }

        if start_time_ts is not None:
            start_time = datetime.fromtimestamp(start_time_ts)
            out["start_time"] = start_time.isoformat()

        if end_time_ts is not None:
            end_time = datetime.fromtimestamp(end_time_ts)
            out["end_time"] = end_time.isoformat()

        if start_time_ts is not None and end_time_ts is not None:
            duration = end_time - start_time
            out["duration"] = str(duration)

        print(json.dumps(out))


def cmd_show_results(args: argparse.Namespace, cursor: sqlite3.Cursor) -> None:
    query = f"""
        SELECT * FROM scan_result WHERE scan_result.run == {args.index}
    """

    if args.failed:
        query += "AND scan_result.success == FALSE"

    query += ";"

    res = cursor.execute(query)

    for line in res:
        (
            id_,
            run_id,
            loader,
            start_time_ts,
            end_time_ts,
            success,
            in_data,
            out_data,
        ) = line

        out = {
            "id": id_,
            "run_id": run_id,
            "loader": loader,
            "success": bool(success),
            "in_data": json.loads(in_data),
            "out_data": json.loads(out_data),
        }

        if start_time_ts is not None:
            start_time = datetime.fromtimestamp(start_time_ts)
            out["start_time"] = start_time.isoformat()

        if end_time_ts is not None:
            end_time = datetime.fromtimestamp(end_time_ts)
            out["end_time"] = end_time.isoformat()

        if start_time_ts is not None and end_time_ts is not None:
            duration = end_time - start_time
            out["duration"] = str(duration)

        print(json.dumps(out))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser.add_argument("--db", type=Path, required=True, help="path to sqlite db")

    runs_parser = subparsers.add_parser("runs", help="show testruns")
    runs_parser.set_defaults(cmd="runs")

    results_parser = subparsers.add_parser("results", help="show testruns")
    results_parser.add_argument(
        "--failed", action="store_true", help="only show failed runs"
    )
    results_parser.add_argument("index")
    results_parser.set_defaults(cmd="results")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db = sqlite3.connect(args.db)
    cur = db.cursor()
    print(args)

    if "cmd" in args:
        match args.cmd:
            case "runs":
                cmd_show_runs(args, cur)
            case "results":
                cmd_show_results(args, cur)


if __name__ == "__main__":
    main()
