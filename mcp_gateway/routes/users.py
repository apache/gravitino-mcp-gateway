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
User info endpoint for Bearer-token callers (used by the CLI 'whoami' command).
"""

from fastapi import APIRouter, Depends

from ..models import User
from ..oauth_auth import get_user_from_bearer_token

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("/me")
async def get_current_user_info(user: User = Depends(get_user_from_bearer_token)):
    """Get information about the currently authenticated user.

    This endpoint is used by the CLI 'whoami' command.
    """
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_service_account": user.is_service_account,
        "team": user.team,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
