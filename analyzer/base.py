from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# CloudTrail event names that stop/delete audit logging
TRAIL_TAMPERING_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
}

# IAM events that create or attach policies
IAM_POLICY_EVENTS = {
    "CreatePolicy",
    "CreatePolicyVersion",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
}

MFA_DELETE_EVENTS = {
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
}


@dataclass
class CtFinding:
    rule_id: str
    severity: str
    event_name: str
    actor: str
    region: str
    event_time: str
    title: str
    detail: str
    remediation: str


@dataclass
class AnalyzeConfig:
    profile: str | None = None
    region: str = "us-east-1"
    lookback_hours: int = 24
    min_severity: str = "LOW"
    login_failure_threshold: int = 3


@dataclass
class TrailEvents:
    events: list[dict] = field(default_factory=list)
