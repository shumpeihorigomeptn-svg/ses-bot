from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .auth import TokenPayload, decode_access_token

http_bearer = HTTPBearer(auto_error=False)


def require_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
) -> TokenPayload:
    """Authorization ヘッダーから JWT を検証し、ユーザー情報を返す."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証トークンが必要です",
        )

    token = credentials.credentials
    try:
        return decode_access_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
