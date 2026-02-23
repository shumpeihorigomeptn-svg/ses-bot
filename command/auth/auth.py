from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import bcrypt
import jwt
from dotenv import load_dotenv
from jwt import InvalidTokenError

from schema.auth_schema import LoginRequest, LoginResponse

load_dotenv()

logger = logging.getLogger(__name__)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
try:
    JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
except ValueError:
    JWT_EXPIRES_MINUTES = 60

__all__ = ["hash_password", "verify_password", "login", "decode_access_token", "TokenPayload"]


def hash_password(password: str) -> str:
    """入力パスワードを bcrypt でハッシュ化する."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """平文パスワードとハッシュの整合性を検証する."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def _create_access_token(subject: str) -> str:
    """JWT アクセストークンを生成."""
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY が設定されていません")

    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRES_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


@dataclass(frozen=True)
class TokenPayload:
    user_id: str
    claims: Dict[str, Any]


def decode_access_token(token: str) -> TokenPayload:
    """JWT を検証し、ペイロードを返す."""
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY が設定されていません")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except InvalidTokenError as exc:
        raise ValueError("トークンが無効です") from exc

    subject = payload.get("sub")
    if not subject:
        raise ValueError("トークンにユーザー情報が含まれていません")

    return TokenPayload(user_id=str(subject), claims=payload)


def login(request: LoginRequest) -> LoginResponse:
    """Supabase に問い合わせてログイン可否を判定し、成功時に JWT を返す."""
    logger.info("Attempting login for username: %s", request.username)

    from database.supa_utils import get_user_from_user_name_and_password

    user = get_user_from_user_name_and_password(request.username, request.password)
    if not user:
        logger.warning("Login failed for username: %s", request.username)
        raise ValueError("Invalid username or password")

    user_id = str(user.get("id") or user.get("user_id") or request.username)
    user_name = str(user.get("user_name") or user.get("username") or request.username)
    token = _create_access_token(user_id)
    logger.info("Login successful for username: %s", request.username)
    return LoginResponse(token=token, token_type="bearer", user_id=user_id, user_name=user_name)
