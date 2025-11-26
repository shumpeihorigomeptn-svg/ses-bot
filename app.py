from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any

import requests
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
DOWNLOAD_DIR = "downloaded_files"


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


def call_proposal_api(
    *,
    api_url: str,
    api_token: str | None,
    case_num: int,
    proposal_link: str,
    candidate_profiles: str,
    skill_sheet: dict[str, Any] | None,
) -> dict[str, Any]:
    headers: dict[str, str] = {}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    data = {
        "case_num": case_num,
        "proposal_link": proposal_link,
        "candidate_profiles": candidate_profiles,
    }
    files = None
    if skill_sheet:
        logger.info(
            "提案書作成APIへファイル送信: name=%s size=%s mime=%s",
            skill_sheet.get("name"),
            skill_sheet.get("size"),
            skill_sheet.get("mimetype"),
        )
        files = {
            "skill_sheet": (
                skill_sheet["name"],
                skill_sheet["content"],
                skill_sheet.get("mimetype", "application/octet-stream"),
            )
        }

    resp = requests.post(api_url, data=data, files=files, headers=headers, timeout=180)
    content_type = resp.headers.get("Content-Type")
    body_snippet = resp.text[:200]

    if resp.status_code >= 400:
        logger.error(
            "提案書作成APIがエラー: status=%s content_type=%s body_snippet=%s",
            resp.status_code,
            content_type,
            body_snippet,
        )
    else:
        logger.info(
            "提案書作成APIレスポンス: status=%s content_type=%s body_snippet=%s",
            resp.status_code,
            content_type,
            body_snippet,
        )

    resp.raise_for_status()
    return resp.json()


def build_app() -> App:
    load_dotenv()  # .envから環境変数を読み込む
    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    app_token = os.environ.get("SLACK_APP_TOKEN")
    proposal_api_url = os.environ.get("PROPOSAL_API_URL")
    proposal_api_token = os.environ.get("PROPOSAL_API_TOKEN")

    if not bot_token or not app_token:
        raise ValueError("環境変数 SLACK_BOT_TOKEN と SLACK_APP_TOKEN を設定してください。")
    if not proposal_api_url:
        raise ValueError("環境変数 PROPOSAL_API_URL を設定してください。")

    app = App(token=bot_token, logger=logger)

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
        say("受け付けました。提案書作成APIに送信します…", thread_ts=thread_ts)

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
                    "API送信に添付: name=%s size=%s mime=%s",
                    skill_sheet.get("name"),
                    skill_sheet.get("size"),
                    skill_sheet.get("mimetype"),
                )
                _save_skill_sheet(skill_sheet)

            try:
                api_resp = call_proposal_api(
                    api_url=proposal_api_url,
                    api_token=proposal_api_token,
                    case_num=case_num_int,
                    proposal_link=permalink,
                    candidate_profiles=fields["提案内容"] or "",
                    skill_sheet=skill_sheet,
                )
                status = api_resp.get("status")
                proposal_id = api_resp.get("proposal_id")
                message = (
                    "提案書作成APIへ送信しました。\n"
                    f"status: {status}, proposal_id: {proposal_id}"
                )
            except Exception as e:
                logger.exception("提案書作成APIの呼び出しに失敗しました")
                message = f"提案書作成APIの呼び出しに失敗しました: {e}"

            say(message, thread_ts=thread_ts)

        threading.Thread(target=worker, daemon=True).start()

    return app, app_token


def main() -> None:
    app, app_token = build_app()
    SocketModeHandler(app, app_token).start()


if __name__ == "__main__":
    main()
