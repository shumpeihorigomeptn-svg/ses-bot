from __future__ import annotations

import logging
from typing import Any, Dict
import os
from dotenv import load_dotenv
load_dotenv(".env")

from postgrest import APIError as PostgrestAPIError
from typing import Any, Dict, Optional

from supabase import Client, create_client

logger = logging.getLogger(__name__)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
_client: Optional[Client] = None


def _get_client() -> Client:
    global _client
    if _client is not None:
        return _client
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL が設定されていません")
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY が設定されていません")
    _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _client

PROMPT_ID = 1
_PROMPT_KEYS = (
    "requirement_system_prompt",
    "proposal_supabase_system_prompt",
    "evaluate_score_system_prompt",
    "make_proposal_system_prompt",
)


def _fetch_prompt_row(prompt_id: int) -> Dict[str, Any]:
    try:
        client = _get_client()
        result = (
            client.table("Prompt")
            .select("*")
            .eq("id", prompt_id)
            .limit(1)
            .execute()
        )
    except PostgrestAPIError as exc:
        logger.warning("Prompt テーブル取得に失敗しました: %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - 実行環境依存
        logger.warning("Prompt 取得時に想定外のエラー: %s", exc)
        return {}

    rows = result.data or []
    if not rows:
        logger.warning("Prompt に id=%s のレコードが見つかりません", prompt_id)
        return {}
    return rows[0]


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
