from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

load_dotenv(".env")

logger = logging.getLogger(__name__)
DEFAULT_DATABASE_URL = (
    "postgresql+psycopg2://postgres:SpeeeOnishiPass1234@/ses-ai"
    "?host=/cloudsql/ses-ainize:asia-northeast1:ses-ai"
)
_db_connect_kwargs: Optional[Dict[str, Any]] = None


def _get_db_connect_kwargs() -> Dict[str, Any]:
    global _db_connect_kwargs
    if _db_connect_kwargs is not None:
        return _db_connect_kwargs

    database_url = (os.getenv("DATABASE_URL") or DEFAULT_DATABASE_URL).strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL が設定されていません")

    normalized_url = database_url
    if normalized_url.startswith("postgresql+psycopg2://"):
        normalized_url = normalized_url.replace("postgresql+psycopg2://", "postgresql://", 1)

    parsed = urlparse(normalized_url)
    dbname = (parsed.path or "").lstrip("/")
    if not dbname:
        raise RuntimeError("DATABASE_URL にデータベース名が含まれていません")

    query_params = parse_qs(parsed.query or "")
    host = (query_params.get("host") or [parsed.hostname])[0]
    if not host:
        raise RuntimeError("DATABASE_URL に host が含まれていません")

    kwargs: Dict[str, Any] = {"dbname": dbname, "host": host}
    if parsed.username:
        kwargs["user"] = unquote(parsed.username)
    if parsed.password is not None:
        kwargs["password"] = unquote(parsed.password)

    port_value = (query_params.get("port") or [parsed.port])[0]
    if port_value is not None and str(port_value) != "":
        try:
            kwargs["port"] = int(port_value)
        except (TypeError, ValueError):
            kwargs["port"] = port_value

    for key, values in query_params.items():
        if key in {"host", "port"} or not values:
            continue
        kwargs[key] = values[0]

    _db_connect_kwargs = kwargs
    return _db_connect_kwargs

PROMPT_ID = 1
_PROMPT_KEYS = (
    "requirement_system_prompt",
    "proposal_supabase_system_prompt",
    "evaluate_score_system_prompt",
    "make_proposal_system_prompt",
)


def _fetch_prompt_row(prompt_id: int) -> Dict[str, Any]:
    try:
        with psycopg2.connect(**_get_db_connect_kwargs()) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM "Prompt" WHERE id = %s LIMIT 1', (prompt_id,))
                row = cur.fetchone()
    except Exception as exc:  # pragma: no cover - 実行環境依存
        logger.warning("Prompt 取得時に想定外のエラー: %s", exc)
        return {}

    if not row:
        logger.warning("Prompt に id=%s のレコードが見つかりません", prompt_id)
        return {}
    return dict(row)


def _get_prompt_values() -> Dict[str, str]:
    # 毎回DBから取得し、未設定時は空文字を返す。
    row = _fetch_prompt_row(PROMPT_ID)
    prompts: Dict[str, str] = {key: "" for key in _PROMPT_KEYS}
    for key in _PROMPT_KEYS:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            prompts[key] = value
    return prompts


def make_requirement_messages(prompt: str):
    prompts = _get_prompt_values()
    messages = [{"role": "system", "content": prompts["requirement_system_prompt"]}]
    messages.append({"role": "user", "content": prompt})
    return messages


def make_evaluate_score_messages(requirement: str, candidates: str):
    prompts = _get_prompt_values()
    messages = [
        {
            "role": "system",
            "content": prompts["evaluate_score_system_prompt"].replace("[requirement]", requirement),
        }
    ]
    messages.append(
        {
            "role": "user",
            "content": f"候補者情報は以下の通り。\nーーーーーーーーー\n{candidates}\nーーーーーーーーー\nです。",
        }
    )
    return messages


def make_proposal_messages(prompt: str):
    prompts = _get_prompt_values()
    messages = [{"role": "system", "content": prompts["proposal_supabase_system_prompt"]}]
    messages.append({"role": "user", "content": prompt})
    return messages


def make_proposal_generation_messages(requirement: str, prompt: str):
    prompts = _get_prompt_values()
    messages = [
        {
            "role": "system",
            "content": prompts["make_proposal_system_prompt"].replace("[requirement]", requirement),
        }
    ]
    messages.append(
        {
            "role": "user",
            "content": (
                "候補者情報は以下の通り。\nーーーーーーーーー\n"
                f"{prompt}\nーーーーーーーーー\nです。評価が高い場合は提案のみを出力してください。"
            ),
        }
    )
    return messages
