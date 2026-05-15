from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

import psycopg2
from dotenv import load_dotenv
from psycopg2 import sql
from psycopg2.extras import Json, RealDictCursor
from pypdf import PdfReader

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

load_dotenv()

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


def _adapt_db_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return Json(value)
    return value


def _db_fetch_one(query: Any, params: tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
    with psycopg2.connect(**_get_db_connect_kwargs()) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            row = cur.fetchone()
    return dict(row) if row else None


def _db_insert_returning(table_name: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not payload:
        raise ValueError("payload is empty")
    columns = list(payload.keys())
    values = [_adapt_db_value(payload[col]) for col in columns]
    query = sql.SQL("INSERT INTO {table} ({columns}) VALUES ({values}) RETURNING *").format(
        table=sql.Identifier(table_name),
        columns=sql.SQL(", ").join(sql.Identifier(col) for col in columns),
        values=sql.SQL(", ").join(sql.Placeholder() for _ in columns),
    )
    return _db_fetch_one(query, tuple(values))


def _db_update_returning(
    table_name: str,
    key_column: str,
    key_value: Any,
    payload: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if not payload:
        raise ValueError("payload is empty")
    columns = list(payload.keys())
    assignments = sql.SQL(", ").join(
        sql.SQL("{} = {}").format(sql.Identifier(col), sql.Placeholder()) for col in columns
    )
    values = [_adapt_db_value(payload[col]) for col in columns]
    query = sql.SQL("UPDATE {table} SET {assignments} WHERE {key} = %s RETURNING *").format(
        table=sql.Identifier(table_name),
        assignments=assignments,
        key=sql.Identifier(key_column),
    )
    return _db_fetch_one(query, tuple(values + [key_value]))


def _get_case_id_from_number(case_num: int) -> str:
    try:
        row = _db_fetch_one(
            """
            SELECT id
            FROM "CaseManagement"
            WHERE number = %s
            LIMIT 1
            """,
            (case_num,),
        )
    except Exception as exc:
        raise RuntimeError(f"CaseManagement 取得に失敗しました: {exc}") from exc
    if not row:
        raise RuntimeError(f"CaseManagement が見つかりません: case_num={case_num}")
    return str(row["id"])


def _get_case_summary(case_id: str) -> str:
    try:
        row = _db_fetch_one(
            """
            SELECT case_summary
            FROM "CaseManagement"
            WHERE id = %s
            LIMIT 1
            """,
            (case_id,),
        )
    except Exception as exc:
        raise RuntimeError(f"CaseManagement 取得に失敗しました: {exc}") from exc
    if not row:
        raise RuntimeError(f"CaseManagement が見つかりません: id={case_id}")
    return row.get("case_summary") or ""


def get_case_user_name_by_number(case_num: int) -> Optional[str]:
    try:
        row = _db_fetch_one(
            """
            SELECT user_name
            FROM "CaseManagement"
            WHERE number = %s
            LIMIT 1
            """,
            (case_num,),
        )
    except Exception as exc:
        raise RuntimeError(f"CaseManagement 取得に失敗しました: {exc}") from exc
    if not row:
        return None
    return row.get("user_name")


def _insert_proposal_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        row = _db_insert_returning("Proposal", payload)
    except Exception as exc:
        raise RuntimeError(f"Proposal への登録に失敗しました: {exc}") from exc
    if not row:
        raise RuntimeError("Proposal 追加結果が空です")
    return row


def _update_proposal_record(proposal_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        row = _db_update_returning("Proposal", "id", proposal_id, payload)
    except Exception as exc:
        raise RuntimeError(f"Proposal 更新に失敗しました: {exc}") from exc
    if not row:
        raise RuntimeError("Proposal 更新結果が空です")
    return row


def _get_bp_id_by_slack_channel(slack_channel_id: str) -> Optional[str]:
    try:
        row = _db_fetch_one(
            """
            SELECT id
            FROM "Bp"
            WHERE slack_channel_id = %s
            LIMIT 1
            """,
            (slack_channel_id,),
        )
    except Exception as exc:
        raise RuntimeError(f"Bp 取得に失敗しました: {exc}") from exc
    return str(row["id"]) if row else None


def _get_proposal_count_by_case(case_id: str) -> int:
    last_exc: Optional[Exception] = None
    for attempt in range(3):
        try:
            row = _db_fetch_one(
                """
                SELECT COUNT(*)::int AS count
                FROM "Proposal"
                WHERE case_id = %s
                """,
                (case_id,),
            )
            last_exc = None
            return int((row or {}).get("count") or 0)
        except Exception as exc:
            last_exc = exc
            logger.warning("Proposal 件数取得に失敗しました (retry %d/3): %s", attempt + 1, exc)
            time.sleep(1 + attempt)
    if last_exc is not None:
        raise RuntimeError(f"Proposal 件数取得に失敗しました: {last_exc}") from last_exc
    return 0


def _extract_skill_sheet_text(skill_sheet: Optional[UploadFile]) -> str:
    if not skill_sheet:
        return ""
    file_obj = getattr(skill_sheet, "file", None) or skill_sheet
    if not hasattr(file_obj, "read"):
        raise ValueError("skill_sheet はファイルオブジェクトではありません")
    current_pos = None
    if hasattr(file_obj, "tell") and hasattr(file_obj, "seek"):
        current_pos = file_obj.tell()
        file_obj.seek(0)
    try:
        reader = PdfReader(file_obj)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        if current_pos is not None:
            file_obj.seek(current_pos)


def _sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename or "").strip()
    if not base:
        return "skill_sheet"
    normalized = re.sub(r"\s+", "_", base)
    normalized = re.sub(r"[^A-Za-z0-9._-]", "_", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("._-")
    return normalized or "skill_sheet"


def _build_object_name(prefix: str, case_num: int, filename: str) -> str:
    safe_prefix = (prefix or "skill-sheets").strip("/").replace("\\", "/")
    if safe_prefix:
        return f"{safe_prefix}/{case_num}/{filename}"
    return f"{case_num}/{filename}"


def upload_skill_sheet_to_gcs(upload_file: UploadFile, case_num: int) -> str:
    if upload_file is None:
        raise ValueError("upload_file is required")

    bucket_name = os.getenv("GCS_BUCKET_NAME")
    if not bucket_name:
        raise RuntimeError("GCS_BUCKET_NAME is not set")

    prefix = os.getenv("GCS_SKILL_SHEET_PREFIX", "skill-sheets")
    project = os.getenv("GOOGLE_CLOUD_PROJECT") or None

    filename = _sanitize_filename(getattr(upload_file, "filename", "") or "skill_sheet")
    object_name = _build_object_name(prefix, case_num, filename)

    from google.cloud import storage

    client = storage.Client(project=project)
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(object_name)

    file_obj = getattr(upload_file, "file", None) or upload_file
    if not hasattr(file_obj, "read"):
        raise ValueError("upload_file must be a file-like object")

    try:
        if hasattr(file_obj, "seek"):
            file_obj.seek(0)
        blob.upload_from_file(file_obj, content_type=getattr(upload_file, "content_type", None))
    finally:
        if hasattr(file_obj, "seek"):
            try:
                file_obj.seek(0)
            except Exception as exc:
                logger.warning("Failed to reset upload_file pointer: %s", exc)

    return object_name


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

    logger.info(
        "Generating proposal for case_num: %s, proposal_link: %s, proposal_bp_handler: %s",
        case_num,
        proposal_link,
        proposal_bp_handler,
    )

    llm_api = LLMAPI()
    prompt = candidate_profiles

    skill_sheet_object_name = None
    if skill_sheet:
        try:
            skill_sheet_object_name = upload_skill_sheet_to_gcs(skill_sheet, case_num)
        except Exception as exc:
            logger.error("Failed to upload skill sheet to GCS: %s", exc)
            raise

    skill_text = _extract_skill_sheet_text(skill_sheet)
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
            base_payload["bp_link"] = proposal_link
        if bp_id:
            base_payload["bp_id"] = bp_id
        if proposal_bp_handler:
            base_payload["proposal_bp_handler"] = proposal_bp_handler
        if skill_sheet_object_name:
            base_payload["skill_sheet_object_name"] = skill_sheet_object_name
        logger.info(
            "Proposal 初回登録 payload: keys=%s proposal_bp_handler=%s",
            sorted(base_payload.keys()),
            base_payload.get("proposal_bp_handler"),
        )

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

        json_response["bp_link"] = proposal_link

        if bp_id:
            json_response["bp_id"] = bp_id
        if proposal_bp_handler:
            json_response["proposal_bp_handler"] = proposal_bp_handler

        proposal_messages = make_proposal_generation_messages(case_summary, prompt)
        proposal_content = llm_api.request_openai(proposal_messages)
        json_response["proposal"] = proposal_content

        if skill_sheet_object_name:
            json_response["skill_sheet_object_name"] = skill_sheet_object_name
        logger.info(
            "Proposal 更新 payload: proposal_id=%s proposal_bp_handler=%s keys=%s",
            proposal_id,
            json_response.get("proposal_bp_handler"),
            sorted(json_response.keys()),
        )

        inserted = _update_proposal_record(proposal_id, json_response)
        logger.info(
            "Proposal 更新完了: proposal_id=%s saved_proposal_bp_handler=%s",
            inserted.get("id"),
            inserted.get("proposal_bp_handler"),
        )
    except Exception as exc:
        logger.error("Error during proposal generation: %s", exc)
        return ProposalResponse(status="error", proposal_id="")

    return ProposalResponse(status="success", proposal_id=inserted.get("id", ""))
