from __future__ import annotations

import json
import re

from .base import (
    IAM_POLICY_EVENTS,
    MFA_DELETE_EVENTS,
    SEVERITY_ORDER,
    TRAIL_TAMPERING_EVENTS,
    AnalyzeConfig,
    CtFinding,
    TrailEvents,
)

_WILDCARD_RE = re.compile(r'"Action"\s*:\s*(?:"\*"|\[.*"\*".*\])', re.DOTALL)


def _actor(event: dict) -> str:
    detail = event.get("_detail", {})
    uid = detail.get("userIdentity", {})
    return uid.get("arn") or uid.get("userName") or uid.get("type") or "unknown"


def _region(event: dict) -> str:
    return event.get("_detail", {}).get("awsRegion") or event.get("AwsRegion", "unknown")


def _time(event: dict) -> str:
    t = event.get("EventTime")
    return t.isoformat() if hasattr(t, "isoformat") else str(t)


def check_root_usage(data: TrailEvents, config: AnalyzeConfig) -> list[CtFinding]:
    """CT-001: Any API activity by the root account."""
    findings = []
    for event in data.events:
        detail = event.get("_detail", {})
        uid = detail.get("userIdentity", {})
        if uid.get("type") == "Root":
            findings.append(CtFinding(
                rule_id="CT-001", severity="CRITICAL",
                event_name=event.get("EventName", "unknown"),
                actor="root",
                region=_region(event),
                event_time=_time(event),
                title="Root account activity detected",
                detail=f"Root account performed '{event.get('EventName')}' at {_time(event)}.",
                remediation="Use IAM users or roles. Revoke root access keys. Enable SCPs to restrict root.",
            ))
    return findings


def check_login_failures(data: TrailEvents, config: AnalyzeConfig) -> list[CtFinding]:
    """CT-002: Multiple console login failures — brute-force indicator."""
    findings = []
    failures: dict[str, list[dict]] = {}
    for event in data.events:
        if event.get("EventName") != "ConsoleLogin":
            continue
        detail = event.get("_detail", {})
        if detail.get("responseElements", {}).get("ConsoleLogin") == "Failure":
            src_ip = detail.get("sourceIPAddress", "unknown")
            failures.setdefault(src_ip, []).append(event)

    threshold = config.login_failure_threshold
    for src_ip, evts in failures.items():
        if len(evts) >= threshold:
            findings.append(CtFinding(
                rule_id="CT-002", severity="HIGH",
                event_name="ConsoleLogin",
                actor=src_ip,
                region=_region(evts[0]),
                event_time=_time(evts[0]),
                title=f"Console login failures from {src_ip} ({len(evts)} attempts)",
                detail=f"{len(evts)} failed console logins from {src_ip} in the lookback window.",
                remediation="Block source IP at WAF/SCP level. Enable MFA. Review account for compromise.",
            ))
    return findings


def check_mfa_deleted(data: TrailEvents, config: AnalyzeConfig) -> list[CtFinding]:
    """CT-003: MFA device deactivated or deleted."""
    findings = []
    for event in data.events:
        if event.get("EventName") in MFA_DELETE_EVENTS:
            findings.append(CtFinding(
                rule_id="CT-003", severity="HIGH",
                event_name=event.get("EventName", "unknown"),
                actor=_actor(event),
                region=_region(event),
                event_time=_time(event),
                title=f"MFA device removed: {event.get('EventName')}",
                detail=f"'{_actor(event)}' removed an MFA device at {_time(event)}.",
                remediation="Re-enable MFA immediately. Audit IAM users for MFA compliance.",
            ))
    return findings


def check_trail_tampering(data: TrailEvents, config: AnalyzeConfig) -> list[CtFinding]:
    """CT-004: CloudTrail logging stopped or trail deleted."""
    findings = []
    for event in data.events:
        if event.get("EventName") in TRAIL_TAMPERING_EVENTS:
            findings.append(CtFinding(
                rule_id="CT-004", severity="CRITICAL",
                event_name=event.get("EventName", "unknown"),
                actor=_actor(event),
                region=_region(event),
                event_time=_time(event),
                title=f"CloudTrail tampered: {event.get('EventName')}",
                detail=f"'{_actor(event)}' performed '{event.get('EventName')}' on CloudTrail at {_time(event)}.",
                remediation="Restore trail. Add SCP/resource policy to prevent trail modification.",
            ))
    return findings


def check_wildcard_iam_change(data: TrailEvents, config: AnalyzeConfig) -> list[CtFinding]:
    """CT-005: IAM policy created/attached with wildcard action."""
    findings = []
    for event in data.events:
        if event.get("EventName") not in IAM_POLICY_EVENTS:
            continue
        detail = event.get("_detail", {})
        req = detail.get("requestParameters", {}) or {}
        policy_doc = req.get("policyDocument", "")
        if isinstance(policy_doc, dict):
            policy_doc = json.dumps(policy_doc)
        if _WILDCARD_RE.search(policy_doc):
            findings.append(CtFinding(
                rule_id="CT-005", severity="HIGH",
                event_name=event.get("EventName", "unknown"),
                actor=_actor(event),
                region=_region(event),
                event_time=_time(event),
                title=f"Wildcard IAM policy created via {event.get('EventName')}",
                detail=f"'{_actor(event)}' created/attached an IAM policy with Action:* at {_time(event)}.",
                remediation="Remove wildcard policy. Enforce least-privilege via SCP and detective controls.",
            ))
    return findings


ALL_RULES = [
    check_root_usage,
    check_login_failures,
    check_mfa_deleted,
    check_trail_tampering,
    check_wildcard_iam_change,
]


def run_all(data: TrailEvents, config: AnalyzeConfig | None = None) -> list[CtFinding]:
    if config is None:
        config = AnalyzeConfig()
    results: list[CtFinding] = []
    for rule in ALL_RULES:
        results.extend(rule(data, config))
    return sorted(results, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
