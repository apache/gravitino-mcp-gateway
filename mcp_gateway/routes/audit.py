# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Audit Log and Analytics API Routes
"""

# pylint cannot see that sqlalchemy.func members are callable.
# pylint: disable=not-callable

import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import desc, func
from sqlalchemy.orm import Query as SqlQuery
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User
from ..oauth_auth import get_user_from_bearer_token

router = APIRouter(prefix="/api/v1/audit", tags=["Audit & Analytics"])


# The longest periods that the days, hours and minutes parameters accept.
MAX_DAYS = 90
MAX_HOURS = 168
MAX_MINUTES = 10080

# The period the analytics cover when none is given.
DEFAULT_PERIOD_DAYS = 7

# The most calls one CSV export holds, the latest first.
EXPORT_ROW_LIMIT = 10000

# Spreadsheets run a cell that starts with one of these as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_CSV_HEADER = [
    "Timestamp (UTC)",
    "User",
    "Service",
    "Tool",
    "Method",
    "Status",
    "Duration (ms)",
    "IP Address",
    "Request Headers",
    "Error",
]


def _pinned_user_id(current_user: User) -> Optional[int]:
    """The one account whose logs the caller may read, or None for an admin, who reads all."""
    return None if current_user.is_admin else current_user.id


def _period_start(
    days: Optional[int],
    hours: Optional[int],
    minutes: Optional[int],
    *,
    default_days: Optional[int] = None,
) -> Optional[datetime]:
    """When the period given in minutes, hours or days began; the first one set counts."""
    now = datetime.utcnow()
    if minutes is not None:
        return now - timedelta(minutes=minutes)
    if hours is not None:
        return now - timedelta(hours=hours)
    if days is not None:
        return now - timedelta(days=days)
    if default_days is not None:
        return now - timedelta(days=default_days)
    return None


def _filtered_logs(
    db: Session,
    pinned_user_id: Optional[int],
    *,
    user_id: Optional[int] = None,
    service: Optional[str] = None,
    tool_name: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> SqlQuery:
    """The audit logs the caller may read, narrowed by the given filters.

    ``pinned_user_id`` comes from ``_pinned_user_id``. While it is set, the logs
    are that account's whatever ``user_id`` says; only an admin reading every
    account's logs may narrow them to another account.
    """
    query = db.query(AuditLog)
    if pinned_user_id is not None:
        query = query.filter(AuditLog.user_id == pinned_user_id)
    elif user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    if service:
        query = query.filter(AuditLog.service == service)
    if tool_name:
        query = query.filter(AuditLog.tool_name == tool_name)
    if status:
        query = query.filter(AuditLog.status == status)
    if start_date:
        query = query.filter(AuditLog.created_at >= start_date)
    if end_date:
        query = query.filter(AuditLog.created_at <= end_date)
    return query


@router.get("/logs")
async def get_audit_logs(
    service: Optional[str] = None,
    tool_name: Optional[str] = None,
    status: Optional[str] = None,
    user_id: Optional[int] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """
    Query audit logs with filtering and pagination.

    Filters:
    - service: Filter by MCP service (e.g., "gravitino")
    - tool_name: Filter by tool name
    - status: Filter by status ("success", "error", "unauthorized", "cancelled")
    - user_id: Filter by user (admins only)
    - start_date: Filter by date range start
    - end_date: Filter by date range end
    """
    query = _filtered_logs(
        db,
        _pinned_user_id(current_user),
        user_id=user_id,
        service=service,
        tool_name=tool_name,
        status=status,
        start_date=start_date,
        end_date=end_date,
    )

    # Get total count
    total_count = query.count()

    # Apply pagination and ordering
    logs = query.order_by(desc(AuditLog.created_at)).limit(limit).offset(offset).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "username": log.username,
                "service": log.service,
                "tool_name": log.tool_name,
                "method": log.method,
                "status": log.status,
                "duration_ms": log.duration_ms,
                "error_message": log.error_message,
                "created_at": log.created_at.isoformat(),
                "request_params": log.request_params,
                "request_headers": log.request_headers,
                "ip_address": log.ip_address,
            }
            for log in logs
        ],
    }


@router.get("/logs/{log_id}")
async def get_audit_log_detail(
    log_id: int,
    current_user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """Get detailed information about a specific audit log entry"""
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    pinned_user_id = _pinned_user_id(current_user)
    if pinned_user_id is not None and log.user_id != pinned_user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "id": log.id,
        "user_id": log.user_id,
        "username": log.username,
        "service": log.service,
        "tool_name": log.tool_name,
        "method": log.method,
        "request_params": log.request_params,
        "request_headers": log.request_headers,
        "response_data": log.response_data,
        "status": log.status,
        "error_message": log.error_message,
        "duration_ms": log.duration_ms,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "created_at": log.created_at.isoformat(),
    }


def _csv_text(value: Optional[str]) -> Optional[str]:
    """Quote logged text so a spreadsheet shows it instead of running it.

    Callers choose tool names, and MCP servers write the error messages.
    """
    if value and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_row(log: AuditLog) -> list:
    """One call as a row under ``_CSV_HEADER``."""
    return [
        log.created_at.isoformat(),
        _csv_text(log.username),
        _csv_text(log.service),
        _csv_text(log.tool_name),
        _csv_text(log.method),
        log.status,
        log.duration_ms,
        _csv_text(log.ip_address),
        _csv_text(json.dumps(log.request_headers)) if log.request_headers else "",
        _csv_text(log.error_message or ""),
    ]


def _render_csv(logs: list) -> str:
    """The calls as a CSV file with a header row."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_CSV_HEADER)
    writer.writerows(_csv_row(log) for log in logs)
    return output.getvalue()


@router.get("/logs/export/csv")
async def export_audit_logs_csv(
    service: Optional[str] = None,
    tool_name: Optional[str] = None,
    status: Optional[str] = None,
    user_id: Optional[int] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    days: Optional[int] = Query(default=None, ge=0, le=MAX_DAYS),
    hours: Optional[int] = Query(default=None, ge=0, le=MAX_HOURS),
    minutes: Optional[int] = Query(default=None, ge=0, le=MAX_MINUTES),
    current_user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """
    Export audit logs as CSV, the latest 10,000 calls at most.

    Takes the filters of GET /logs. Without start_date, days, hours or minutes
    give the period instead.
    """
    logs = (
        _filtered_logs(
            db,
            _pinned_user_id(current_user),
            user_id=user_id,
            service=service,
            tool_name=tool_name,
            status=status,
            start_date=start_date or _period_start(days, hours, minutes),
            end_date=end_date,
        )
        .order_by(desc(AuditLog.created_at))
        .limit(EXPORT_ROW_LIMIT)
        .all()
    )
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        content=_render_csv(logs),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_logs_{stamp}.csv"},
    )


@router.get("/analytics/summary")
async def get_analytics_summary(  # pylint: disable=too-many-locals
    days: Optional[int] = Query(default=None, ge=0, le=MAX_DAYS),
    hours: Optional[int] = Query(default=None, ge=0, le=MAX_HOURS),
    minutes: Optional[int] = Query(default=None, ge=0, le=MAX_MINUTES),
    service: Optional[str] = None,
    tool_name: Optional[str] = None,
    user_id: Optional[int] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(get_user_from_bearer_token),
    db: Session = Depends(get_db),
):
    """
    Usage figures for a period: from start_date to end_date, or the last 7 days
    unless days, hours or minutes say otherwise.

    Takes the filters of GET /logs other than status, so the figures count the
    calls the log list shows.
    """
    pinned_user_id = _pinned_user_id(current_user)
    logs = _filtered_logs(
        db,
        pinned_user_id,
        user_id=user_id,
        service=service,
        tool_name=tool_name,
        start_date=start_date
        or _period_start(days, hours, minutes, default_days=DEFAULT_PERIOD_DAYS),
        end_date=end_date,
    )
    succeeded = logs.filter(AuditLog.status == "success")

    total_calls = logs.count()
    successful_calls = succeeded.count()
    success_rate = (successful_calls / total_calls * 100) if total_calls > 0 else 0
    avg_duration = (
        logs.filter(AuditLog.duration_ms.isnot(None))
        .with_entities(func.avg(AuditLog.duration_ms))
        .scalar()
        or 0
    )

    # Most used services and tools (successful calls only)
    services = (
        succeeded.with_entities(
            AuditLog.service, func.count(AuditLog.id).label("count")
        )
        .group_by(AuditLog.service)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    tools = (
        succeeded.with_entities(
            AuditLog.tool_name, AuditLog.service, func.count(AuditLog.id).label("count")
        )
        .group_by(AuditLog.tool_name, AuditLog.service)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    errors_by_service = (
        logs.filter(AuditLog.status == "error")
        .with_entities(AuditLog.service, func.count(AuditLog.id).label("error_count"))
        .group_by(AuditLog.service)
        .all()
    )

    # Who made the calls, only for an admin reading every account's logs
    active_users = None
    if pinned_user_id is None:
        active_users = (
            logs.join(User, User.id == AuditLog.user_id)
            .with_entities(User.username, func.count(AuditLog.id).label("call_count"))
            .group_by(User.username)
            .order_by(desc("call_count"))
            .limit(10)
            .all()
        )

    if start_date is not None:
        period_label = f"from {start_date.isoformat()}" + (
            f" to {end_date.isoformat()}" if end_date else ""
        )
    elif minutes is not None:
        period_label = f"{minutes} minutes"
    elif hours is not None:
        period_label = f"{hours} hours"
    else:
        period_label = f"{days if days is not None else DEFAULT_PERIOD_DAYS} days"

    return {
        "period": period_label,
        "total_calls": total_calls,
        "successful_calls": successful_calls,
        "success_rate": round(success_rate, 2),
        "average_response_time_ms": round(avg_duration, 2),
        "top_services": [{"service": s.service, "calls": s.count} for s in services],
        "top_tools": [
            {"tool": t.tool_name, "service": t.service, "calls": t.count} for t in tools
        ],
        "active_users": (
            None
            if active_users is None
            else [{"username": u.username, "calls": u.call_count} for u in active_users]
        ),
        "errors_by_service": [
            {"service": e.service, "errors": e.error_count} for e in errors_by_service
        ],
    }
