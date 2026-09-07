import json
from datetime import datetime, timezone

from analyzer.base import AnalyzeConfig, TrailEvents
from analyzer.rules import (
    check_login_failures,
    check_mfa_deleted,
    check_root_usage,
    check_trail_tampering,
    check_wildcard_iam_change,
    run_all,
)

CFG = AnalyzeConfig()
NOW = datetime.now(timezone.utc)


def _event(name: str, uid_type: str = "IAMUser", uid_arn: str = "arn:aws:iam::123:user/bob",
           region: str = "us-east-1", extra_detail: dict | None = None) -> dict:
    detail = {
        "eventName": name,
        "awsRegion": region,
        "userIdentity": {"type": uid_type, "arn": uid_arn},
        "requestParameters": {},
        "responseElements": {},
    }
    if extra_detail:
        detail.update(extra_detail)
    return {"EventName": name, "EventTime": NOW, "_detail": detail}


def _login_failure(src_ip: str = "1.2.3.4") -> dict:
    return {
        "EventName": "ConsoleLogin",
        "EventTime": NOW,
        "_detail": {
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": src_ip,
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/bob"},
            "responseElements": {"ConsoleLogin": "Failure"},
        },
    }


# --- CT-001 Root usage ---

def test_root_usage_flagged():
    event = _event("GetCallerIdentity", uid_type="Root", uid_arn="arn:aws:iam::123:root")
    data = TrailEvents(events=[event])
    findings = check_root_usage(data, CFG)
    assert any(f.rule_id == "CT-001" and f.severity == "CRITICAL" for f in findings)


def test_iam_user_not_root():
    event = _event("GetCallerIdentity", uid_type="IAMUser")
    data = TrailEvents(events=[event])
    findings = check_root_usage(data, CFG)
    assert findings == []


def test_multiple_root_events_all_flagged():
    events = [_event("ListBuckets", uid_type="Root"), _event("DescribeInstances", uid_type="Root")]
    data = TrailEvents(events=events)
    findings = check_root_usage(data, CFG)
    assert len(findings) == 2


def test_empty_events_clean():
    data = TrailEvents(events=[])
    findings = check_root_usage(data, CFG)
    assert findings == []


# --- CT-002 Login failures ---

def test_login_failures_threshold():
    events = [_login_failure("5.5.5.5")] * 3
    data = TrailEvents(events=events)
    findings = check_login_failures(data, CFG)
    assert any(f.rule_id == "CT-002" and "5.5.5.5" in f.actor for f in findings)


def test_login_failures_below_threshold():
    events = [_login_failure("5.5.5.5")] * 2
    data = TrailEvents(events=events)
    findings = check_login_failures(data, CFG)
    assert findings == []


def test_login_failures_custom_threshold():
    config = AnalyzeConfig(login_failure_threshold=5)
    events = [_login_failure("9.9.9.9")] * 4
    data = TrailEvents(events=events)
    findings = check_login_failures(data, config)
    assert findings == []


def test_login_success_not_flagged():
    event = {
        "EventName": "ConsoleLogin", "EventTime": NOW,
        "_detail": {"eventName": "ConsoleLogin", "awsRegion": "us-east-1",
                    "sourceIPAddress": "1.1.1.1",
                    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/alice"},
                    "responseElements": {"ConsoleLogin": "Success"}},
    }
    data = TrailEvents(events=[event] * 5)
    findings = check_login_failures(data, CFG)
    assert findings == []


# --- CT-003 MFA deleted ---

def test_deactivate_mfa_flagged():
    event = _event("DeactivateMFADevice")
    data = TrailEvents(events=[event])
    findings = check_mfa_deleted(data, CFG)
    assert any(f.rule_id == "CT-003" and f.severity == "HIGH" for f in findings)


def test_delete_virtual_mfa_flagged():
    event = _event("DeleteVirtualMFADevice")
    data = TrailEvents(events=[event])
    findings = check_mfa_deleted(data, CFG)
    assert any(f.rule_id == "CT-003" for f in findings)


def test_create_mfa_not_flagged():
    event = _event("CreateVirtualMFADevice")
    data = TrailEvents(events=[event])
    findings = check_mfa_deleted(data, CFG)
    assert findings == []


# --- CT-004 Trail tampering ---

def test_stop_logging_flagged():
    event = _event("StopLogging")
    data = TrailEvents(events=[event])
    findings = check_trail_tampering(data, CFG)
    assert any(f.rule_id == "CT-004" and f.severity == "CRITICAL" for f in findings)


def test_delete_trail_flagged():
    event = _event("DeleteTrail")
    data = TrailEvents(events=[event])
    findings = check_trail_tampering(data, CFG)
    assert any(f.rule_id == "CT-004" for f in findings)


def test_describe_trails_not_flagged():
    event = _event("DescribeTrails")
    data = TrailEvents(events=[event])
    findings = check_trail_tampering(data, CFG)
    assert findings == []


# --- CT-005 Wildcard IAM change ---

def test_create_policy_wildcard_flagged():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    event = _event("CreatePolicy", extra_detail={"requestParameters": {"policyDocument": doc}})
    data = TrailEvents(events=[event])
    findings = check_wildcard_iam_change(data, CFG)
    assert any(f.rule_id == "CT-005" for f in findings)


def test_put_role_policy_wildcard_flagged():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    event = _event("PutRolePolicy", extra_detail={"requestParameters": {"policyDocument": doc}})
    data = TrailEvents(events=[event])
    findings = check_wildcard_iam_change(data, CFG)
    assert any(f.rule_id == "CT-005" for f in findings)


def test_create_policy_specific_actions_clean():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    event = _event("CreatePolicy", extra_detail={"requestParameters": {"policyDocument": doc}})
    data = TrailEvents(events=[event])
    findings = check_wildcard_iam_change(data, CFG)
    assert findings == []


# --- run_all ---

def test_run_all_sorted_by_severity():
    root = _event("GetCallerIdentity", uid_type="Root")
    stop = _event("StopLogging")
    mfa = _event("DeactivateMFADevice")
    data = TrailEvents(events=[root, stop, mfa])
    findings = run_all(data, CFG)
    assert len(findings) >= 3
    from analyzer.base import SEVERITY_ORDER
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))


def test_run_all_clean():
    data = TrailEvents(events=[_event("DescribeInstances")])
    findings = run_all(data, CFG)
    assert findings == []


def test_login_failures_different_ips_separate():
    """Failures from different IPs counted independently."""
    events = [_login_failure("1.1.1.1")] * 3 + [_login_failure("2.2.2.2")] * 2
    data = TrailEvents(events=events)
    findings = check_login_failures(data, CFG)
    actors = [f.actor for f in findings]
    assert "1.1.1.1" in actors
    assert "2.2.2.2" not in actors


def test_update_trail_flagged():
    event = _event("UpdateTrail")
    data = TrailEvents(events=[event])
    findings = check_trail_tampering(data, CFG)
    assert any(f.rule_id == "CT-004" and "UpdateTrail" in f.event_name for f in findings)
