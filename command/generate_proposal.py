from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from postgrest import APIError as PostgrestAPIError
from supabase import Client, create_client

try:
    from fastapi import UploadFile
except ImportError:  # pragma: no cover - FastAPI が無い環境向けのフォールバック
    UploadFile = Any  # type: ignore

from command.llm_wrapper.llm_wrapper import LLMAPI
from command.llm_wrapper.prompt import (
    make_evaluate_score_messages,
    make_proposal_generation_messages,
    make_proposal_messages,
)
from schema.api_schema import ProposalResponse
from skill_sheet_text import extract_skill_sheet_text_safe

load_dotenv()

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


def _get_case_id_from_number(case_num: int) -> str:
    client = _get_client()
    try:
        result = (
            client.table("CaseManagement")
            .select("id")
            .eq("number", case_num)
            .limit(1)
            .execute()
        )
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Supabase CaseManagement 取得に失敗しました: {exc}") from exc
    rows = result.data or []
    if not rows:
        raise RuntimeError(f"CaseManagement が見つかりません: case_num={case_num}")
    return rows[0]["id"]


def _get_case_summary(case_id: str) -> str:
    client = _get_client()
    try:
        result = (
            client.table("CaseManagement")
            .select("case_summary")
            .eq("id", case_id)
            .limit(1)
            .execute()
        )
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Supabase CaseManagement 取得に失敗しました: {exc}") from exc
    rows = result.data or []
    if not rows:
        raise RuntimeError(f"CaseManagement が見つかりません: id={case_id}")
    return rows[0]["case_summary"]


def _insert_proposal_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    client = _get_client()
    try:
        result = client.table("Proposal").insert(payload).execute()
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Proposal への登録に失敗しました: {exc}") from exc
    rows = result.data or []
    if not rows:
        raise RuntimeError("Proposal 追加結果が空です")
    return rows[0]


def _update_proposal_record(proposal_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    client = _get_client()
    try:
        result = client.table("Proposal").update(payload).eq("id", proposal_id).execute()
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Proposal 更新に失敗しました: {exc}") from exc
    rows = result.data or []
    if not rows:
        raise RuntimeError("Proposal 更新結果が空です")
    return rows[0]


def _get_bp_id_by_slack_channel(slack_channel_id: str) -> Optional[str]:
    client = _get_client()
    try:
        result = (
            client.table("Bp")
            .select("id")
            .eq("slack_channel_id", slack_channel_id)
            .limit(1)
            .execute()
        )
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Bp 取得に失敗しました: {exc}") from exc
    rows = result.data or []
    if rows:
        return rows[0]["id"]
    return None


def _get_proposal_count_by_case(case_id: str) -> int:
    client = _get_client()
    try:
        result = (
            client.table("Proposal")
            .select("id", count="exact")
            .eq("case_id", case_id)
            .execute()
        )
    except PostgrestAPIError as exc:
        raise RuntimeError(f"Proposal 件数取得に失敗しました: {exc}") from exc
    if result.count is not None:
        return result.count
    return len(result.data or [])


def generate_proposal(
    *,
    case_num: int,
    candidate_profiles: str,
    proposal_link: Optional[str] = None,
    skill_sheet: Optional[UploadFile] = None,
    proposal_bp_handler: Optional[str] = None,
) -> ProposalResponse:
    """
    Slack Bot などから直接呼び出せる提案生成ロジック.
    """

    logger.info("Generating proposal for case_num: %s, proposal_link: %s", case_num, proposal_link)

    llm_api = LLMAPI()
    prompt = candidate_profiles

    skill_text, skill_sheet_warning = extract_skill_sheet_text_safe(skill_sheet)
    if skill_text:
        prompt += "\n\nスキルシートの内容:\n" + skill_text

    try:
        case_id = _get_case_id_from_number(case_num)
        proposal_count = _get_proposal_count_by_case(case_id)
        proposal_code = f"ID_{case_num}_{proposal_count + 1}"

        case_summary = _get_case_summary(case_id)
        if case_summary is None:
            logger.warning("case_summary is None for case_id=%s", case_id)
            case_summary = ""

        slack_channel_id = None
        if proposal_link and "cid=" in proposal_link:
            slack_channel_id = proposal_link.split("cid=")[-1].split("&")[0]
        bp_id = None
        if slack_channel_id:
            try:
                bp_id = _get_bp_id_by_slack_channel(slack_channel_id)
                if not bp_id:
                    logger.warning("Slackチャンネル %s に紐づくBPが見つかりません", slack_channel_id)
            except Exception as exc:  # ログ用途
                logger.error("BP取得に失敗しました: %s", exc)

        base_payload: Dict[str, Any] = {
            "case_id": case_id,
            "proposal_code": proposal_code,
        }
        if proposal_link is not None:
            base_payload["proposal_link"] = proposal_link
        if bp_id:
            base_payload["bp_id"] = bp_id
        if proposal_bp_handler:
            base_payload["proposal_bp_handler"] = proposal_bp_handler

        inserted = _insert_proposal_record(base_payload)
        proposal_id = inserted.get("id")
        if not proposal_id:
            raise RuntimeError("Proposal ID の取得に失敗しました")

        messages = make_proposal_messages(prompt)
        response = llm_api.request_openai(messages)
        response = response.strip()
        start_index = response.find("{")
        end_index = response.rfind("}") + 1
        if start_index == -1 or end_index == 0:
            raise ValueError("Response does not contain valid JSON object")
        json_response = json.loads(response[start_index:end_index])
        json_response["case_id"] = case_id
        json_response["proposal_code"] = proposal_code
        json_response["bp_proposal_text"] = candidate_profiles
        score_messages = make_evaluate_score_messages(case_summary, prompt)
        score_response = llm_api.request_openai(score_messages).strip()
        if score_response.isdigit():
            score_value = int(score_response)
            json_response["score"] = score_value
            json_response["proposal_status"] = score_value >= 80
        else:
            start_index = score_response.find("{")
            end_index = score_response.rfind("}") + 1
            if start_index != -1 and end_index != 0:
                try:
                    score_json = json.loads(score_response[start_index:end_index])
                    json_response["score"] = score_json.get("score")
                    json_response["evaluation"] = score_json.get("evaluation")
                    json_response["proposal_status"] = (
                        score_json.get("score") is not None and score_json.get("score") >= 80
                    )
                except json.JSONDecodeError:
                    logger.warning("Failed to decode score response JSON")

        json_response["proposal_link"] = proposal_link

        if bp_id:
            json_response["bp_id"] = bp_id
        if proposal_bp_handler:
            json_response["proposal_bp_handler"] = proposal_bp_handler

        proposal_messages = make_proposal_generation_messages(case_summary, prompt)
        proposal_content = llm_api.request_openai(proposal_messages)
        json_response["proposal"] = proposal_content

        inserted = _update_proposal_record(proposal_id, json_response)
    except Exception as exc:
        logger.error("Error during proposal generation: %s", exc)
        return ProposalResponse(status="error", proposal_id="", warning=skill_sheet_warning)

    return ProposalResponse(status="success", proposal_id=inserted.get("id", ""), warning=skill_sheet_warning)
