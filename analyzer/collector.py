from __future__ import annotations

from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from .base import AnalyzeConfig, TrailEvents


def collect(config: AnalyzeConfig) -> TrailEvents:
    session = boto3.Session(profile_name=config.profile, region_name=config.region)
    ct = session.client("cloudtrail")
    data = TrailEvents()

    start_time = datetime.now(timezone.utc) - timedelta(hours=config.lookback_hours)

    paginator = ct.get_paginator("lookup_events")
    try:
        for page in paginator.paginate(StartTime=start_time):
            for event in page.get("Events", []):
                # Attach parsed CloudTrailEvent JSON if available
                raw = event.get("CloudTrailEvent", "{}")
                import json
                try:
                    event["_detail"] = json.loads(raw)
                except (ValueError, TypeError):
                    event["_detail"] = {}
                data.events.append(event)
    except ClientError:
        pass

    return data
