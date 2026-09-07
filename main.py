from __future__ import annotations

import argparse
import sys

from analyzer.base import AnalyzeConfig
from analyzer.collector import collect
from analyzer.rules import run_all
from report import print_json, print_terminal, write_csv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-cloudtrail-analyzer",
        description="Analyze CloudTrail logs for security threats and anomalies.",
    )
    p.add_argument("--profile", help="AWS CLI profile name")
    p.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    p.add_argument("--hours", type=int, default=24,
                   help="Lookback window in hours (default: 24)")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--output", choices=["terminal", "json"], default="terminal")
    p.add_argument("--csv-path", metavar="PATH", help="Also write CSV report to PATH")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="Exit with code 2 if any CRITICAL finding is detected")
    p.add_argument("--login-failure-threshold", type=int, default=3,
                   help="Number of failed logins to flag as brute force (default: 3)")
    return p


def main() -> None:
    args = build_parser().parse_args()
    config = AnalyzeConfig(
        profile=args.profile,
        region=args.region,
        lookback_hours=args.hours,
        min_severity=args.min_severity,
        login_failure_threshold=args.login_failure_threshold,
    )
    data = collect(config)
    findings = run_all(data, config)

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical and any(f.severity == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
