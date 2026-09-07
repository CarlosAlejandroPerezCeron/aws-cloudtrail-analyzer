# aws-cloudtrail-analyzer

Scan AWS CloudTrail logs for security threats: root activity, brute-force logins, MFA removal, trail tampering, and wildcard IAM changes.

![CI](https://github.com/CarlosAlejandroPerezCeron/aws-cloudtrail-analyzer/actions/workflows/ci.yml/badge.svg)

## Rules

| ID | Severity | Trigger |
|----|----------|---------|
| CT-001 | CRITICAL | Root account API activity |
| CT-002 | HIGH | Console login failures ≥ threshold (default 3) from same IP |
| CT-003 | HIGH | MFA device deactivated or deleted |
| CT-004 | CRITICAL | CloudTrail stopped, deleted, or modified |
| CT-005 | HIGH | IAM policy created/attached with wildcard Action |

## Install

```bash
pip install boto3 rich
```

## Usage

```bash
python main.py --hours 48 --min-severity HIGH
python main.py --output json | jq .
python main.py --csv-path findings.csv --fail-on-critical
python main.py --profile prod --region eu-west-1 --login-failure-threshold 5
```

## Dev

```bash
pip install pytest pytest-cov ruff
ruff check .
pytest tests/ -v --cov=analyzer --cov=report
```

## Project structure

```
aws-cloudtrail-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── base.py        # dataclasses, event sets, severity map
│   ├── collector.py   # CloudTrail API pagination
│   └── rules.py       # 5 detection rules + run_all()
├── tests/
│   └── test_analyzer.py  # 21 unit tests, no AWS mocking required
├── report.py          # rich terminal table, JSON, CSV output
├── main.py            # CLI entrypoint
└── .github/workflows/ci.yml
```
