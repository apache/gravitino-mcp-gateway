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

"""Deletes rows that have expired, and audit rows older than AUDIT_RETENTION_DAYS.

Anyone can start a device sign-in or a connect flow, so their rows would
otherwise pile up.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .models import AuditLog, DeviceCode, OAuthState, SlackTokenApproval

logger = logging.getLogger(__name__)

# Tables whose rows carry an expires_at after which they are of no use.
EXPIRING_TABLES = (DeviceCode, OAuthState, SlackTokenApproval)
PURGE_INTERVAL = timedelta(minutes=15)


def purge_expired_rows(db: Optional[Session] = None) -> int:
    """Delete the expired rows of every expiring table, and return how many."""
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        now = datetime.utcnow()
        deleted = sum(
            db.query(table)
            .filter(table.expires_at <= now)
            .delete(synchronize_session=False)
            for table in EXPIRING_TABLES
        )
        if settings.AUDIT_RETENTION_DAYS:
            deleted += (
                db.query(AuditLog)
                .filter(
                    AuditLog.created_at
                    < now - timedelta(days=settings.AUDIT_RETENTION_DAYS)
                )
                .delete(synchronize_session=False)
            )
        db.commit()
        if deleted:
            logger.info("Purged %d expired row(s)", deleted)
        return deleted
    except Exception:  # pylint: disable=broad-exception-caught
        db.rollback()
        logger.exception("Failed to purge expired rows")
        return 0
    finally:
        if own_session:
            db.close()


async def _purge_loop() -> None:
    while True:
        await asyncio.to_thread(purge_expired_rows)
        await asyncio.sleep(PURGE_INTERVAL.total_seconds())


def start_purge_task() -> asyncio.Task:
    """Start the background task that deletes expired rows."""
    return asyncio.create_task(_purge_loop())
