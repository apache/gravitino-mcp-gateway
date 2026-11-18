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
Database configuration and session management
"""

import ssl
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


def _with_utf8mb4(url: str) -> str:
    """Append charset=utf8mb4 without breaking an existing query string."""
    charset_param = "charset=utf8mb4"
    if "?" not in url:
        return f"{url}?{charset_param}"
    return url if charset_param in url else f"{url}&{charset_param}"


def _mysql_tls_args(ssl_mode: str, ca_file: Optional[str]) -> dict:
    """PyMySQL connect arguments for a MySQL --ssl-mode value."""
    if ssl_mode == "DISABLED":
        return {"ssl_disabled": True}
    if ssl_mode == "PREFERRED":
        return {}
    context = ssl.create_default_context(cafile=ca_file)
    if ssl_mode == "REQUIRED":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif ssl_mode == "VERIFY_CA":
        context.check_hostname = False
    return {"ssl": context}


# Configure connection args based on database type
connect_args = {}
pool_config = {"pool_pre_ping": True, "echo": False}  # Disable SQLAlchemy query logging

if "sqlite" in settings.DATABASE_URL:
    connect_args = {"check_same_thread": False}
elif "mysql" in settings.DATABASE_URL:
    pool_config.update(
        {
            "pool_size": settings.DATABASE_POOL_SIZE,
            "max_overflow": settings.DATABASE_MAX_OVERFLOW,
            # MySQL closes idle connections after wait_timeout, 8 hours by default.
            "pool_recycle": 3600,
            "pool_timeout": 30,
        }
    )
    connect_args = {
        "charset": "utf8mb4",
        **_mysql_tls_args(settings.DATABASE_SSL_MODE, settings.DATABASE_SSL_CA),
    }

# Create SQLAlchemy engine with utf8mb4 for MySQL
if "mysql" in settings.DATABASE_URL:
    engine = create_engine(
        _with_utf8mb4(settings.DATABASE_URL), connect_args=connect_args, **pool_config
    )
else:
    engine = create_engine(
        settings.DATABASE_URL, connect_args=connect_args, **pool_config
    )

# Create session factory
# expire_on_commit=False keeps loaded attributes available after commit
# so fire-and-forget background tasks can safely read scalar values.
SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, expire_on_commit=False, bind=engine
)

# MySQL tables hold any Unicode text. Other databases ignore mysql_ options.
MYSQL_TABLE_OPTIONS = {
    "mysql_charset": "utf8mb4",
    "mysql_collate": "utf8mb4_unicode_ci",
}


class Base(DeclarativeBase):  # pylint: disable=too-few-public-methods
    """Base class of the gateway's models.

    A model with table arguments of its own ends them with MYSQL_TABLE_OPTIONS.
    """

    __table_args__ = MYSQL_TABLE_OPTIONS


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
