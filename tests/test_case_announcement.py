"""/case-announcement の送信ロジック（_build_case_announcement_parent_text / _process_case_announcement）のテスト。"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module


def _make_client(
    *,
    post_side_effect: Any = None,
    permalink_side_effect: Any = None,
) -> MagicMock:
    client = MagicMock()
    if post_side_effect is not None:
        client.chat_postMessage.side_effect = post_side_effect
    else:
        client.chat_postMessage.return_value = {"ok": True, "ts": "1700.001"}
    if permalink_side_effect is not None:
        client.chat_getPermalink.side_effect = permalink_side_effect
    else:
        client.chat_getPermalink.return_value = {
            "ok": True,
            "permalink": "https://slack.example/p1700001",
        }
    return client


def _payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case_id": "case-uuid-1",
        "main_text": "📢【新規案件のご案内】No.214 ECサイトリニューアル PM支援",
        "thread_text": "【案件詳細】No.214\n・スキル: PM経験3年以上",
        "user_name": "大西",
        "targets": [
            {
                "bp_id": "bp-1",
                "bp_name": "A社",
                "slack_channel_id": "C001",
                "case_sheet_url": "https://docs.google.com/spreadsheets/d/abc",
            }
        ],
    }
    base.update(overrides)
    return base


class TestBuildParentText:
    def test_mention_main_and_sheet_link(self):
        text = app_module._build_case_announcement_parent_text(
            main_text="本文です",
            mention_id="U05CP9LLACX",
            case_sheet_url="https://example.com/sheet",
        )
        assert text.splitlines()[0] == "担当: <@U05CP9LLACX>"
        assert "本文です" in text
        assert "<https://example.com/sheet|貴社向け案件一覧>" in text

    def test_without_mention(self):
        text = app_module._build_case_announcement_parent_text(
            main_text="本文です",
            mention_id=None,
            case_sheet_url=None,
        )
        assert "担当:" not in text
        assert "案件紹介シート" not in text
        assert text.strip() == "本文です"

    def test_without_sheet_url_omits_link_line(self):
        text = app_module._build_case_announcement_parent_text(
            main_text="本文です",
            mention_id="U05CP9LLACX",
            case_sheet_url="",
        )
        assert "案件紹介シート" not in text


class TestResolveMention:
    def test_explicit_slack_id_wins(self):
        assert (
            app_module._resolve_case_announcement_mention_id(
                user_name="大西", user_slack_id="U999"
            )
            == "U999"
        )

    def test_user_list_fallback(self):
        assert (
            app_module._resolve_case_announcement_mention_id(
                user_name="大西", user_slack_id=None
            )
            == app_module.USER_LIST["大西"]
        )

    def test_unknown_user_returns_none(self):
        assert (
            app_module._resolve_case_announcement_mention_id(
                user_name="存在しない", user_slack_id=None
            )
            is None
        )


class TestProcessCaseAnnouncement:
    def test_all_sent_posts_parent_and_thread(self):
        client = _make_client()
        body, status = app_module._process_case_announcement(client, _payload())
        assert status == 200
        assert body["status"] == "ok"
        assert body["case_id"] == "case-uuid-1"
        result = body["results"][0]
        assert result["status"] == "sent"
        assert result["channel"] == "C001"
        assert result["ts"] == "1700.001"
        assert result["permalink"] == "https://slack.example/p1700001"
        assert result["reason"] is None
        # 親投稿＋スレッド返信の2回
        assert client.chat_postMessage.call_count == 2
        parent_call = client.chat_postMessage.call_args_list[0]
        thread_call = client.chat_postMessage.call_args_list[1]
        assert parent_call.kwargs["channel"] == "C001"
        assert "thread_ts" not in parent_call.kwargs
        assert thread_call.kwargs["thread_ts"] == "1700.001"
        assert "【案件詳細】" in thread_call.kwargs["text"]

    def test_parent_text_contains_mention_and_sheet_link(self):
        client = _make_client()
        app_module._process_case_announcement(client, _payload())
        parent_text = client.chat_postMessage.call_args_list[0].kwargs["text"]
        assert f"<@{app_module.USER_LIST['大西']}>" in parent_text
        assert "<https://docs.google.com/spreadsheets/d/abc|貴社向け案件一覧>" in parent_text

    def test_empty_thread_text_skips_thread_post(self):
        client = _make_client()
        body, _ = app_module._process_case_announcement(
            client, _payload(thread_text="")
        )
        assert client.chat_postMessage.call_count == 1
        assert body["results"][0]["status"] == "sent"

    def test_missing_channel_is_skipped(self):
        client = _make_client()
        payload = _payload(
            targets=[{"bp_id": "bp-2", "bp_name": "B社", "slack_channel_id": None}]
        )
        body, status = app_module._process_case_announcement(client, payload)
        assert status == 200
        result = body["results"][0]
        assert result["status"] == "skipped"
        assert result["reason"] == "slack_channel_id 未設定"
        client.chat_postMessage.assert_not_called()

    def test_post_failure_is_failed_with_reason(self):
        error = app_module.SlackApiError(
            message="err", response={"ok": False, "error": "channel_not_found"}
        )
        client = _make_client(post_side_effect=error)
        body, status = app_module._process_case_announcement(client, _payload())
        # 全targetがfailedなので502
        assert status == 502
        result = body["results"][0]
        assert result["status"] == "failed"
        assert result["reason"] == "channel_not_found"

    def test_partial_failure_returns_200(self):
        error = app_module.SlackApiError(
            message="err", response={"ok": False, "error": "is_archived"}
        )
        ok_response = {"ok": True, "ts": "1700.001"}
        # target1: 親OK→スレッドOK / target2: 親でエラー
        client = _make_client(post_side_effect=[ok_response, ok_response, error])
        payload = _payload(
            targets=[
                {"bp_id": "bp-1", "bp_name": "A社", "slack_channel_id": "C001"},
                {"bp_id": "bp-2", "bp_name": "B社", "slack_channel_id": "C002"},
            ]
        )
        body, status = app_module._process_case_announcement(client, payload)
        assert status == 200
        statuses = [r["status"] for r in body["results"]]
        assert statuses == ["sent", "failed"]

    def test_all_skipped_returns_200(self):
        client = _make_client()
        payload = _payload(
            targets=[
                {"bp_id": "bp-1", "bp_name": "A社", "slack_channel_id": ""},
                {"bp_id": "bp-2", "bp_name": "B社", "slack_channel_id": None},
            ]
        )
        _, status = app_module._process_case_announcement(client, payload)
        assert status == 200

    def test_permalink_failure_keeps_sent(self):
        error = app_module.SlackApiError(
            message="err", response={"ok": False, "error": "message_not_found"}
        )
        client = _make_client(permalink_side_effect=error)
        body, status = app_module._process_case_announcement(client, _payload())
        assert status == 200
        result = body["results"][0]
        assert result["status"] == "sent"
        assert result["permalink"] is None
        assert result["reason"] == "permalink_fetch_failed"

    def test_thread_post_failure_is_partial(self):
        error = app_module.SlackApiError(
            message="err", response={"ok": False, "error": "rate_limited"}
        )
        ok_response = {"ok": True, "ts": "1700.001"}
        # 親OK→スレッドでエラー
        client = _make_client(post_side_effect=[ok_response, error])
        body, status = app_module._process_case_announcement(client, _payload())
        assert status == 200
        result = body["results"][0]
        assert result["status"] == "partial"
        assert result["ts"] == "1700.001"
        assert result["reason"] == "thread_post_failed"

    def test_missing_parent_ts_is_failed(self):
        client = _make_client()
        client.chat_postMessage.return_value = {"ok": True}  # tsなし
        body, status = app_module._process_case_announcement(client, _payload())
        assert status == 502
        result = body["results"][0]
        assert result["status"] == "failed"
        assert result["reason"] == "missing_parent_ts"
        # スレッド返信・permalink取得に進まない
        assert client.chat_postMessage.call_count == 1
        client.chat_getPermalink.assert_not_called()

    def test_client_confidential_fields_never_posted(self):
        """client_budget / client_name がペイロードに混入しても投稿本文に現れない。"""
        client = _make_client()
        payload = _payload(
            client_name="極秘クライアント株式会社",
            client_budget="120万円",
        )
        app_module._process_case_announcement(client, payload)
        for call in client.chat_postMessage.call_args_list:
            assert "極秘クライアント株式会社" not in call.kwargs["text"]
            assert "120万円" not in call.kwargs["text"]


class TestValidation:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"case_id": ""},
            {"main_text": ""},
            {"main_text": None},
            {"targets": []},
            {"targets": None},
        ],
    )
    def test_invalid_payload_returns_400(self, overrides):
        client = _make_client()
        body, status = app_module._process_case_announcement(
            client, _payload(**overrides)
        )
        assert status == 400
        assert "error" in body
        client.chat_postMessage.assert_not_called()

    def test_non_dict_target_is_failed(self):
        client = _make_client()
        payload = _payload(
            targets=[
                "C001",
                {"bp_id": "bp-1", "bp_name": "A社", "slack_channel_id": "C001"},
            ]
        )
        body, status = app_module._process_case_announcement(client, payload)
        assert status == 200
        assert body["results"][0]["status"] == "failed"
        assert body["results"][0]["reason"] == "invalid_target"
        assert body["results"][1]["status"] == "sent"

    @pytest.mark.parametrize("payload", [["a"], "text", 123])
    def test_non_dict_payload_returns_400(self, payload):
        client = _make_client()
        body, status = app_module._process_case_announcement(client, payload)
        assert status == 400
        assert "error" in body
        client.chat_postMessage.assert_not_called()


class TestFixedTemplate:
    def test_preview_matches_post_for_each_bp(self):
        announcement = {
            "title": "No.123 製造業PM", "introduction": "紹介文", "pitch": "→ PM募集\n（80〜100% ／ 東京 ／ 10月）",
            "closing": "ご提案はワークフローからお願いします。\nご提案、お待ちしています！",
        }
        payload = _payload(announcement=announcement, main_text="", targets=[
            {"bp_id": "bp-1", "slack_channel_id": "C1", "case_sheet_url": "https://example.com/a"},
            {"bp_id": "bp-2", "slack_channel_id": "C2", "case_sheet_url": None},
        ])
        preview, status = app_module._preview_case_announcement(payload)
        assert status == 200
        client = _make_client()
        _, status = app_module._process_case_announcement(client, payload)
        assert status == 200
        parents = [call.kwargs["text"] for call in client.chat_postMessage.call_args_list if "thread_ts" not in call.kwargs]
        assert parents == [item["text"] for item in preview["previews"]]
        assert parents[0].splitlines()[:3] == ["📢【新規案件のご案内】", "No.123 製造業PM", ""]
        assert len(parents[0].split("\n\n")) == 5
        assert parents[0].count("ご不明点") == 1
        assert "案件紹介シート" not in parents[1]
        assert len(parents[1].split("\n\n")) == 5
        assert parents[0].endswith("ご不明点は <@U05CP9LLACX> までお願いします。")

    @pytest.mark.parametrize("announcement", [{}, [], {"title":"見出し", "introduction":" ", "pitch":"募集", "closing":""}])
    def test_invalid_structured_body_never_posts(self, announcement):
        client = _make_client()
        payload = _payload(announcement=announcement)
        assert app_module._preview_case_announcement(payload)[1] == 400
        assert app_module._process_case_announcement(client, payload)[1] == 400
        client.chat_postMessage.assert_not_called()

    def test_unresolved_contact_and_empty_closing_do_not_make_blank_final_block(self):
        payload = _payload(user_name="未登録", announcement={"title":"No.1 案件", "introduction":"紹介", "pitch":"募集", "closing":""})
        body, status = app_module._preview_case_announcement(payload)
        assert status == 200
        assert "ご不明点" not in body["previews"][0]["text"]
        assert not body["previews"][0]["text"].endswith("\n")
