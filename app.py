from __future__ import annotations

import io
import logging
import os
import re
import threading
from urllib.parse import parse_qs, unquote, urlparse
from types import SimpleNamespace
from typing import Any

import psycopg2
import requests
from dotenv import load_dotenv
from flask import Flask, request
from psycopg2.extras import RealDictCursor
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from generate_proposal import (
    generate_proposal as generate_proposal_internal,
    get_case_user_name_by_number,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
DOWNLOAD_DIR = "downloaded_files"
USER_LIST = {
    "大西": "U05CP9LLACX",
    "上水流": "U05QS9W48G1",
    "近藤": "U063M8RD4G4",
    "山田": "U099D00B78B",
    "堀越": "U09J0DN3BHA",
}
DEFAULT_DATABASE_URL = (
    "postgresql+psycopg2://postgres:SpeeeOnishiPass1234@/ses-ai"
    "?host=/cloudsql/ses-ainize:asia-northeast1:ses-ai"
)
_db_connect_kwargs: dict[str, Any] | None = None


def _clean_lines(text: str) -> list[str]:
    without_mentions = re.sub(r"<@[^>]+>", "", text)
    return [line.strip() for line in without_mentions.splitlines() if line.strip()]


def _extract_section(text: str, keywords: list[str], stop_keywords: list[str]) -> str | None:
    lines = _clean_lines(text)
    for idx, line in enumerate(lines):
        matched_keyword = next((kw for kw in keywords if kw in line), None)
        if not matched_keyword:
            continue

        # キーワードと同じ行に値が書かれている場合
        after_keyword = re.sub(rf"^.*?{re.escape(matched_keyword)}[:：]?\s*", "", line).strip()
        collected: list[str] = []
        if after_keyword:
            collected.append(after_keyword)

        # 次の行以降をストップキーワードまで収集
        for following in lines[idx + 1 :]:
            if any(stop in following for stop in stop_keywords):
                break
            collected.append(following)

        return "\n".join(collected).strip() if collected else None

    return None


def extract_request_fields(text: str) -> dict[str, str | None]:
    project_id = _extract_section(
        text,
        ["案件番号を記載ください", "案件番号を記載してください", "案件番号"],
        ["提案内容を記載ください", "提案内容を記載してください", "提案内容"],
    )
    proposal = _extract_section(
        text,
        ["提案内容を記載ください", "提案内容を記載してください", "提案内容"],
        ["案件番号を記載ください", "案件番号を記載してください", "案件番号"],
    )

    return {"案件番号": project_id, "提案内容": proposal}


def _download_first_file(files: list[dict[str, Any]], bot_token: str) -> dict[str, Any] | None:
    """Slack添付のうち、最初のファイルをダウンロードして返す。"""
    for file_info in files:
        url = file_info.get("url_private_download") or file_info.get("url_private")
        name = file_info.get("name")
        mimetype = file_info.get("mimetype") or "application/octet-stream"
        if not url or not name:
            continue

        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {bot_token}"}, timeout=20)
            status = resp.status_code
            ctype = resp.headers.get("Content-Type", "")
            logger.info("添付ダウンロード応答: status=%s content_type=%s", status, ctype)
            resp.raise_for_status()

            # HTMLが返ってきた場合は認可不足の可能性が高い（files:read 未付与など）
            if "text/html" in ctype:
                logger.warning(
                    "期待したファイルではなくHTMLが返却されました。files:read スコープ不足などを確認してください。"
                )
                return None

            content = resp.content
            size = len(content)
            logger.info("添付ファイルをダウンロードしました: name=%s size=%d mime=%s", name, size, mimetype)
            return {"name": name, "content": content, "mimetype": mimetype, "size": size}
        except Exception:
            logger.exception("添付ファイルのダウンロードに失敗しました")

    return None


def _save_skill_sheet(skill_sheet: dict[str, Any]) -> str | None:
    """ダウンロード済みのファイルをローカルに保存してパスを返す。"""
    try:
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        filename = os.path.basename(skill_sheet.get("name") or "skill_sheet")
        dest_path = os.path.join(DOWNLOAD_DIR, filename)
        with open(dest_path, "wb") as f:
            f.write(skill_sheet.get("content") or b"")
        logger.info("添付ファイルを保存しました: path=%s size=%s", dest_path, skill_sheet.get("size"))
        return dest_path
    except Exception:
        logger.exception("添付ファイルの保存に失敗しました")
        return None


def _to_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _to_upload_file(skill_sheet: dict[str, Any] | None) -> Any | None:
    """generate_proposal に渡せる UploadFile 互換オブジェクトを組み立てる。"""
    if not skill_sheet:
        return None
    content = skill_sheet.get("content")
    if content is None:
        return None
    buf = io.BytesIO(content)
    buf.seek(0)
    return SimpleNamespace(
        file=buf,
        filename=skill_sheet.get("name"),
        content_type=skill_sheet.get("mimetype", "application/octet-stream"),
    )


def _parse_message_ts_from_permalink_path(path: str) -> str | None:
    for segment in (path or "").split("/"):
        if not segment.startswith("p"):
            continue
        raw = segment[1:]
        if raw.isdigit() and len(raw) > 6:
            return f"{raw[:-6]}.{raw[-6:]}"
    return None


def _parse_slack_permalink(permalink: str) -> tuple[str | None, str | None]:
    if not permalink:
        return None, None
    try:
        parsed = urlparse(permalink)
    except Exception:
        return None, None

    channel_id = None
    thread_ts = None

    query = parse_qs(parsed.query or "")
    if query.get("cid"):
        channel_id = query["cid"][0]
    if query.get("thread_ts"):
        thread_ts = query["thread_ts"][0]

    if not channel_id:
        parts = (parsed.path or "").split("/")
        if "archives" in parts:
            idx = parts.index("archives")
            if len(parts) > idx + 1:
                channel_id = parts[idx + 1]

    if not thread_ts:
        thread_ts = _parse_message_ts_from_permalink_path(parsed.path or "")

    return channel_id, thread_ts


def _normalize_decision(decision: str | None) -> str | None:
    if decision is None:
        return None

    if isinstance(decision, bool):
        return "提案" if decision else "見送り"

    value = str(decision).strip()
    if not value:
        return None

    lowered = value.lower()
    if "見送" in value or lowered in {
        "false",
        "0",
        "ng",
        "reject",
        "rejected",
        "decline",
        "declined",
        "postpone",
        "postponed",
    }:
        return "見送り"
    if "提案" in value or lowered in {"true", "1", "ok", "propose", "proposal", "proposed"}:
        return "提案"
    return None


def _build_bp_decision_message(
    *,
    bp_link: str | None,
    candidate_initials: str | None,
    decision: str,
    comment: str | None,
) -> str:
    candidate_label = f"{candidate_initials}さん" if candidate_initials else "候補者さん"

    if decision == "見送り":
        link_text = f"<{bp_link}|こちら>" if bp_link else "こちら"
        message = (
            f"{link_text}で提案いただいた{candidate_label}は見送らせていただきました。"
            "詳細は担当者からご確認ください。"
        )
        if comment:
            message += f"\n担当者コメント：{comment}"
        return message

    lead_action = "提案いただいた" if decision == "提案" else "共有いただいた"
    if bp_link:
        link_text = f"<{bp_link}|こちら>"
        lead = f"{link_text}で{lead_action}"
    else:
        lead = f"こちらで{lead_action}"

    message = f"{lead}{candidate_label}をクライアントに{decision}しました！"
    if comment:
        message += f"\n担当者コメント：{comment}"
    return message


def _get_db_connect_kwargs() -> dict[str, Any]:
    global _db_connect_kwargs
    if _db_connect_kwargs is not None:
        return _db_connect_kwargs

    database_url = (os.getenv("DATABASE_URL") or DEFAULT_DATABASE_URL).strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL を設定してください。")

    normalized_url = database_url
    if normalized_url.startswith("postgresql+psycopg2://"):
        normalized_url = normalized_url.replace("postgresql+psycopg2://", "postgresql://", 1)

    parsed = urlparse(normalized_url)
    dbname = (parsed.path or "").lstrip("/")
    if not dbname:
        raise RuntimeError("DATABASE_URL にデータベース名が含まれていません。")

    query_params = parse_qs(parsed.query or "")
    host = (query_params.get("host") or [parsed.hostname])[0]
    if not host:
        raise RuntimeError("DATABASE_URL に host が含まれていません。")

    kwargs: dict[str, Any] = {
        "dbname": dbname,
        "host": host,
    }
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


def _db_fetch_one(sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    with psycopg2.connect(**_get_db_connect_kwargs()) as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
    return dict(row) if row else None


def _db_execute(sql: str, params: tuple[Any, ...]) -> int:
    with psycopg2.connect(**_get_db_connect_kwargs()) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row_count = cur.rowcount
    return row_count


def _fetch_proposal_by_code(proposal_code: str) -> dict[str, Any] | None:
    try:
        return _db_fetch_one(
            """
            SELECT id, case_id, candidate_initials, interview_schedule_url
            FROM "Proposal"
            WHERE proposal_code = %s
            LIMIT 1
            """,
            (proposal_code,),
        )
    except Exception as exc:
        raise RuntimeError(f"Proposal の取得に失敗しました: {exc}") from exc


def _fetch_case_by_id(case_id: str) -> dict[str, Any] | None:
    try:
        return _db_fetch_one(
            """
            SELECT id, user_id, user_name, client_id
            FROM "CaseManagement"
            WHERE id = %s
            LIMIT 1
            """,
            (case_id,),
        )
    except Exception as exc:
        raise RuntimeError(f"CaseManagement の取得に失敗しました: {exc}") from exc


def _fetch_user_name_by_id(user_id: str) -> str | None:
    try:
        row = _db_fetch_one(
            """
            SELECT id, user_name
            FROM "User"
            WHERE id = %s
            LIMIT 1
            """,
            (user_id,),
        )
    except Exception as exc:
        raise RuntimeError(f"User の取得に失敗しました: {exc}") from exc
    if not row:
        return None
    return row.get("user_name")


def _fetch_client_name_by_id(client_id: str) -> str | None:
    try:
        row = _db_fetch_one(
            """
            SELECT id, client_name
            FROM "Clients"
            WHERE id = %s
            LIMIT 1
            """,
            (client_id,),
        )
    except Exception as exc:
        raise RuntimeError(f"Clients の取得に失敗しました: {exc}") from exc
    if not row:
        return None
    return row.get("client_name")


def _update_interview_schedule_url_by_code(proposal_code: str, interview_schedule_url: str) -> None:
    try:
        updated_count = _db_execute(
            """
            UPDATE "Proposal"
            SET interview_schedule_url = %s
            WHERE proposal_code = %s
            """,
            (interview_schedule_url, proposal_code),
        )
    except Exception as exc:
        raise RuntimeError(f"Proposal の更新に失敗しました: {exc}") from exc
    if updated_count <= 0:
        raise RuntimeError("Proposal の更新結果が空です")


def _format_client_label(client_name: str | None) -> str:
    if not client_name:
        return "クライアント"
    name = client_name.strip()
    if not name:
        return "クライアント"
    if name.endswith("社"):
        return name
    if any(token in name for token in ("株式会社", "有限会社", "合同会社")):
        return name
    return f"{name}社"


def _normalize_next_status(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized in {"first_interview", "1次", "一次面談", "1次面談"}:
        return "1次"
    if normalized in {"final_interview", "最終", "最終面談"}:
        return "最終"
    return value.strip()


def _format_japanese_date(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    match = re.match(r"^(\d{4})[./-](\d{1,2})[./-](\d{1,2})$", text)
    if not match:
        return text
    try:
        year, month, day = (int(part) for part in match.groups())
    except ValueError:
        return text
    return f"{year}年{month}月{day}日"


def _resolve_proposal_context(
    proposal_code: str,
    candidate_initial: str | None,
) -> dict[str, Any]:
    proposal_row = _fetch_proposal_by_code(proposal_code)
    if not proposal_row:
        raise LookupError("proposal_code に一致する Proposal が見つかりません")

    candidate_initial = (candidate_initial or proposal_row.get("candidate_initials") or "").strip()

    interview_schedule_url = (proposal_row.get("interview_schedule_url") or "").strip() or None

    case_id = proposal_row.get("case_id")
    if not case_id:
        raise ValueError("Proposal に case_id が紐づいていません")

    case_row = _fetch_case_by_id(str(case_id))
    if not case_row:
        raise LookupError("case_id に一致する CaseManagement が見つかりません")

    user_name = None
    user_id = case_row.get("user_id")
    if user_id:
        try:
            user_name = _fetch_user_name_by_id(str(user_id))
        except Exception as exc:
            logger.exception("User の取得に失敗しました: %s", exc)
    if not user_name:
        user_name = (case_row.get("user_name") or "").strip() or None

    mention_label = user_name or "担当者"
    if user_name:
        slack_id = USER_LIST.get(user_name.strip())
        if slack_id:
            mention_label = f"<@{slack_id}>"

    client_name = None
    client_id = case_row.get("client_id")
    if client_id:
        try:
            client_name = _fetch_client_name_by_id(str(client_id))
        except Exception as exc:
            logger.exception("Clients の取得に失敗しました: %s", exc)

    return {
        "candidate_initial": candidate_initial,
        "mention_label": mention_label,
        "client_name": client_name,
        "interview_schedule_url": interview_schedule_url,
    }


def _build_proposal_update_thread_text(
    *,
    bp_link: str | None,
    candidate_initial: str,
    client_name: str | None,
    mention_label: str,
) -> str:
    link_text = f"<{bp_link}|こちらのスレッド>" if bp_link else "こちらのスレッド"
    candidate_label = f"{candidate_initial}さん" if candidate_initial else "候補者さん"
    client_label = _format_client_label(client_name)
    return (
        f"{link_text}でご提案いただいた{candidate_label}ですが、\n"
        f"クライアントの{client_label}より面談依頼をいただきました！\n\n"
        "つきましては、日程調整に進みたく以下をご教示いただけますと幸いです\n"
        "• 面談可能な候補日（複数）\n"
        "• フルネーム\n"
        "• 最新の並行状況（件数／選考ステータス／選考結果の判明予定日など）\n\n"
        f"補足があれば、{mention_label}より連絡いたします！"
    )


def _build_proposal_detail_update_text(
    *,
    candidate_initial: str,
    next_status: str,
    date_text: str,
    mention_label: str,
) -> str:
    candidate_label = f"{candidate_initial}さん" if candidate_initial else "候補者さん"
    if mention_label == "担当者":
        contact_text = "詳細は担当者よりご連絡いたします！"
    else:
        contact_text = f"詳細は担当者（{mention_label}）よりご連絡いたします！"
    return (
        f"{candidate_label}の{next_status}面談日は、{date_text}となりました。\n"
        "ご調整のほど、よろしくお願いいたします！\n"
        f"{contact_text}"
    )


def build_app() -> App:
    load_dotenv()  # .envから環境変数を読み込む
    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    signing_secret = os.environ.get("SLACK_SIGNING_SECRET")

    if not bot_token or not signing_secret:
        raise ValueError("環境変数 SLACK_BOT_TOKEN と SLACK_SIGNING_SECRET を設定してください。")

    app = App(token=bot_token, signing_secret=signing_secret, logger=logger)

    @app.event("app_mention")
    def handle_app_mention(event, say):
        logger.info("app_mention を受信: %s", event)
        thread_ts = event.get("thread_ts") or event.get("ts")
        text = event.get("text") or ""
        user = event.get("user")
        channel = event.get("channel")
        message_ts = event.get("ts")
        files = event.get("files") or []
        logger.info("添付ファイル数: %d", len(files))
        
        text = text.replace("\n", "").replace("*", "")
        fields = extract_request_fields(text)
        logger.info("抽出結果: user=%s fields=%s", user, fields)

        missing = [name for name, value in fields.items() if not value]
        if missing:
            message = (
                "メッセージから必要な情報を読み取れませんでした。"
                f" 確認できなかった項目: {', '.join(missing)}"
            )
            say(message, thread_ts=thread_ts)
            return

        case_num_int = _to_int(fields["案件番号"])
        if case_num_int is None:
            say("案件番号は数字で入力してください。", thread_ts=thread_ts)
            return

        # まず受け付けメッセージを即返信して、時間のかかる処理は別スレッドへ
        mention_text = None
        try:
            case_user_name = get_case_user_name_by_number(case_num_int)
        except Exception:
            logger.exception("案件担当者の取得に失敗しました")
            case_user_name = None

        if case_user_name:
            case_user_name = case_user_name.strip()
            slack_id = USER_LIST.get(case_user_name)
            if slack_id:
                mention_text = f"<@{slack_id}>"
            else:
                logger.warning("USER_LIST に担当者が存在しません: user_name=%s", case_user_name)

        if mention_text:
            say(f"{mention_text} 確認お願いします！", thread_ts=thread_ts)
        else:
            say("確認いたします！", thread_ts=thread_ts)

        def worker():
            permalink = ""
            if channel and message_ts:
                try:
                    resp = app.client.chat_getPermalink(channel=channel, message_ts=message_ts)
                    permalink = resp.get("permalink") or ""
                except Exception:
                    logger.exception("メッセージリンクの取得に失敗しました")

            skill_sheet = _download_first_file(files, bot_token) if files else None
            if files and not skill_sheet:
                logger.warning("添付ファイルがありましたがダウンロードに失敗しました")
            if skill_sheet:
                logger.info(
                    "generate_proposal に添付: name=%s size=%s mime=%s",
                    skill_sheet.get("name"),
                    skill_sheet.get("size"),
                    skill_sheet.get("mimetype"),
                )
                _save_skill_sheet(skill_sheet)
            upload_file = _to_upload_file(skill_sheet)

            try:
                api_resp = generate_proposal_internal(
                    case_num=case_num_int,
                    candidate_profiles=fields["提案内容"] or "",
                    proposal_link=permalink,
                    skill_sheet=upload_file,
                )
                status = getattr(api_resp, "status", None) or getattr(api_resp, "get", lambda k: None)("status")
                proposal_id = getattr(api_resp, "proposal_id", None) or getattr(api_resp, "get", lambda k: None)(
                    "proposal_id"
                )
                message = None
            except Exception as e:
                logger.exception("generate_proposal の呼び出しに失敗しました")
                message = f"generate_proposal の呼び出しに失敗しました: {e}"

            if message:
                say(message, thread_ts=thread_ts)

        threading.Thread(target=worker, daemon=True).start()

    return app


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))

    app = build_app()
    flask_app = Flask(__name__)
    handler = SlackRequestHandler(app)

    @flask_app.route("/slack/events", methods=["POST"])
    def slack_events():
        return handler.handle(request)

    @flask_app.route("/speee-proposal", methods=["POST"])
    def speee_proposal():
        payload = request.get_json(silent=True) or {}
        print(payload)
        if not payload:
            return {"error": "JSONボディが必要です"}, 400

        bp_link = (payload.get("bp_link") or "").strip() or None
        candidate_initials = (payload.get("candidate_initials") or "").strip() or None
        comment = (payload.get("comment") or "").strip() or None
        decision_raw = payload.get("decision") or payload.get("speee_decision")
        proposal_status = payload.get("proposal_status")

        decision = _normalize_decision(decision_raw)
        logger.info(
            "speee_proposal decision parse: decision_raw=%r normalized=%r proposal_status=%r proposal_status_type=%s",
            decision_raw,
            decision,
            proposal_status,
            type(proposal_status).__name__,
        )
        if decision is None:
            if proposal_status is True:
                decision = "提案"
            elif proposal_status is False:
                decision = "見送り"

        final_decision = decision or "提案/見送り"
        logger.info("speee_proposal decision resolved: final_decision=%r", final_decision)

        message = _build_bp_decision_message(
            bp_link=bp_link,
            candidate_initials=candidate_initials,
            decision=final_decision,
            comment=comment,
        )

        channel_id = None
        thread_ts = None
        if bp_link:
            channel_id, thread_ts = _parse_slack_permalink(bp_link)
        if not channel_id:
            channel_id = (payload.get("bp_channel_id") or os.environ.get("BP_CHANNEL_ID") or "").strip() or None

        if not channel_id:
            return {
                "error": "bp_link からチャンネルを判定できません。bp_channel_id または BP_CHANNEL_ID を指定してください。",
            }, 400

        try:
            kwargs = {"channel": channel_id, "text": message}
            if thread_ts:
                kwargs["thread_ts"] = thread_ts
            resp = app.client.chat_postMessage(**kwargs)
        except Exception as exc:
            logger.exception("Slack投稿に失敗しました: %s", exc)
            return {"error": "Slack投稿に失敗しました"}, 500

        return {
            "status": "ok",
            "channel": channel_id,
            "thread_ts": thread_ts,
            "ts": resp.get("ts"),
        }, 200

    @flask_app.route("/proposal-update", methods=["POST"])
    def proposal_update():
        payload = request.get_json(silent=True) or {}
        if not payload:
            return {"error": "JSONボディが必要です"}, 400

        bp_link = (payload.get("bp_link") or "").strip() or None
        proposal_code = (payload.get("proposal_code") or "").strip()
        candidate_initial = (
            (payload.get("candidate_initial") or payload.get("candidate_initials") or "").strip()
        )
        if not proposal_code:
            return {"error": "proposal_code は必須です"}, 400

        try:
            proposal_row = _fetch_proposal_by_code(proposal_code)
        except Exception as exc:
            logger.exception("Proposal の取得に失敗しました: %s", exc)
            return {"error": "Proposal の取得に失敗しました"}, 500

        if not proposal_row:
            return {"error": "proposal_code に一致する Proposal が見つかりません"}, 404

        if not candidate_initial:
            candidate_initial = (proposal_row.get("candidate_initials") or "").strip()

        case_id = proposal_row.get("case_id")
        if not case_id:
            return {"error": "Proposal に case_id が紐づいていません"}, 400

        try:
            case_row = _fetch_case_by_id(str(case_id))
        except Exception as exc:
            logger.exception("CaseManagement の取得に失敗しました: %s", exc)
            return {"error": "CaseManagement の取得に失敗しました"}, 500

        if not case_row:
            return {"error": "case_id に一致する CaseManagement が見つかりません"}, 404

        user_id = case_row.get("user_id")
        client_id = case_row.get("client_id")
        user_name = None
        if user_id:
            try:
                user_name = _fetch_user_name_by_id(str(user_id))
            except Exception as exc:
                logger.exception("User の取得に失敗しました: %s", exc)
        if not user_name:
            user_name = (case_row.get("user_name") or "").strip() or None

        client_name = None
        if client_id:
            try:
                client_name = _fetch_client_name_by_id(str(client_id))
            except Exception as exc:
                logger.exception("Clients の取得に失敗しました: %s", exc)

        mention_label = user_name or "担当者"
        if user_name:
            slack_id = USER_LIST.get(user_name.strip())
            if slack_id:
                mention_label = f"<@{slack_id}>"

        channel_id = None
        if bp_link:
            channel_id, _ = _parse_slack_permalink(bp_link)
        if not channel_id:
            channel_id = (payload.get("bp_channel_id") or os.environ.get("BP_CHANNEL_ID") or "").strip() or None

        if not channel_id:
            return {
                "error": "bp_link からチャンネルを判定できません。bp_channel_id または BP_CHANNEL_ID を指定してください。",
            }, 400

        parent_text = (payload.get("parent_text") or "面談日程調整のスレッドを作成しました。").strip()
        default_thread_text = _build_proposal_update_thread_text(
            bp_link=bp_link,
            candidate_initial=candidate_initial,
            client_name=client_name,
            mention_label=mention_label,
        )
        thread_text = (payload.get("thread_text") or default_thread_text).strip()

        try:
            parent_resp = app.client.chat_postMessage(channel=channel_id, text=parent_text)
            parent_ts = parent_resp.get("ts")
            if not parent_ts:
                raise RuntimeError("親投稿の ts が取得できませんでした")
            thread_resp = app.client.chat_postMessage(
                channel=channel_id,
                text=thread_text,
                thread_ts=parent_ts,
            )
            permalink_resp = app.client.chat_getPermalink(channel=channel_id, message_ts=parent_ts)
            interview_schedule_url = permalink_resp.get("permalink") or ""
            if not interview_schedule_url:
                raise RuntimeError("スレッドURLの取得に失敗しました")
            _update_interview_schedule_url_by_code(proposal_code, interview_schedule_url)
        except Exception as exc:
            logger.exception("Slack投稿に失敗しました: %s", exc)
            return {"error": "Slack投稿に失敗しました"}, 500

        return {
            "status": "ok",
            "channel": channel_id,
            "parent_ts": parent_ts,
            "thread_ts": thread_resp.get("ts"),
            "interview_schedule_url": interview_schedule_url,
        }, 200

    @flask_app.route("/proposal_detail_update", methods=["POST"])
    def proposal_detail_update():
        payload = request.get_json(silent=True) or {}
        if not payload:
            return {"error": "JSONボディが必要です"}, 400

        bp_link = (payload.get("bp_link") or "").strip() or None
        proposal_code = (payload.get("proposal_code") or "").strip()
        candidate_initial = (
            (payload.get("candidate_initial") or payload.get("candidate_initials") or "").strip()
        )
        next_status_raw = payload.get("next_status")
        date_raw = payload.get("date")

        if not proposal_code:
            return {"error": "proposal_code は必須です"}, 400

        try:
            context = _resolve_proposal_context(proposal_code, candidate_initial)
        except ValueError as exc:
            return {"error": str(exc)}, 400
        except LookupError as exc:
            return {"error": str(exc)}, 404
        except Exception as exc:
            logger.exception("Proposal context の取得に失敗しました: %s", exc)
            return {"error": "Proposal context の取得に失敗しました"}, 500

        next_status = _normalize_next_status(next_status_raw)
        if not next_status:
            return {"error": "next_status は必須です（一次 or 最終）"}, 400

        date_text = _format_japanese_date(date_raw)
        if not date_text:
            return {"error": "date は必須です（YYYY/MM/DD）"}, 400

        interview_schedule_url = context.get("interview_schedule_url") or bp_link
        if not interview_schedule_url:
            return {"error": "Proposal に interview_schedule_url が設定されていません（bp_link も未指定）"}, 400

        channel_id, thread_ts = _parse_slack_permalink(interview_schedule_url)
        if not channel_id or not thread_ts:
            return {"error": "interview_schedule_url/bp_link からチャンネルID/スレッドTSを取得できません"}, 400

        message = _build_proposal_detail_update_text(
            candidate_initial=context["candidate_initial"],
            next_status=next_status,
            date_text=date_text,
            mention_label=context["mention_label"],
        )

        try:
            resp = app.client.chat_postMessage(
                channel=channel_id,
                text=message,
                thread_ts=thread_ts,
            )
        except Exception as exc:
            logger.exception("Slack投稿に失敗しました: %s", exc)
            return {"error": "Slack投稿に失敗しました"}, 500

        return {
            "status": "ok",
            "channel": channel_id,
            "thread_ts": thread_ts,
            "ts": resp.get("ts"),
            "interview_schedule_url": interview_schedule_url,
        }, 200

    @flask_app.route("/", methods=["GET"])
    def healthcheck():
        return "ok", 200

    flask_app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
