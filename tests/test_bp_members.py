"""Slackを呼ばず、参加者分類・ページング・案内送信の契約を検証する。"""
from unittest.mock import MagicMock
import pytest
from flask import Flask
from bp_members import channel_members, resolve_users, create_bp_members_blueprint
from case_announcement_layout import build_parent_text
import app as bot


def client():
    c = MagicMock()
    c.auth_test.return_value = {"team_id": "TOWN", "enterprise_id": "EOWN"}
    c.conversations_members.side_effect = [
        {"members": ["U1", "U2"], "response_metadata": {"next_cursor": "next"}},
        {"members": ["U2", "U3", "U4", "U5", "U6", "U7"]},
    ]
    def user(user):
        extra = {
            "U1": {"team_id": "TEXT"}, "U2": {"team_id": "TOWN"},
            "U3": {"team_id": "TEXT", "is_bot": True},
            "U4": {"team_id": "TOTHER", "enterprise_user": {"enterprise_id": "EOWN"}},
            "U5": {"team_id": "TEXT", "deleted": True}, "U6": {},
            "U7": {"team_id": "TOTHER", "enterprise_user": {"teams": ["TOWN"]}},
        }[user]
        return {"user": {"id": user, "profile": {"display_name": "名前" + user}, **extra}}
    c.users_info.side_effect = user
    return c


def test_pagination_and_own_bot_deleted_unknown_are_disabled():
    c = client()
    members = channel_members(c, "C123")
    assert [m["id"] for m in members if m["selectable"]] == ["U1"]
    assert len(members) == 7
    assert members[0]["display_name"] == "名前U1"
    assert c.conversations_members.call_args.kwargs["cursor"] == "next"


def test_partial_failure_is_not_returned_as_complete_selection():
    c = client()
    c.users_info.side_effect = RuntimeError("rate_limited")
    with pytest.raises(RuntimeError):
        channel_members(c, "C123")


def test_resolver_deduplicates_without_member_lookup_and_falls_back():
    c = client()
    assert resolve_users(c, ["U1", "U1"])[0]["display_name"] == "名前U1"
    c.conversations_members.assert_not_called()
    c.users_info.side_effect = RuntimeError("down")
    assert resolve_users(c, ["U1"]) == [{"id": "U1", "display_name": "U1", "resolved": False}]


def test_readonly_routes_fail_recover_and_reject_bad_input():
    c = client()
    server = Flask(__name__)
    server.register_blueprint(create_bp_members_blueprint(c))
    http = server.test_client()
    assert http.get('/bp-members?channel_id=C123').status_code == 200
    assert http.get('/bp-members?channel_id=bad').status_code == 400
    assert http.post('/bp-users', json={"user_ids": ["U1><!here"]}).status_code == 400
    c.conversations_members.side_effect = RuntimeError("down")
    assert http.get('/bp-members?channel_id=C123').status_code == 502
    c.chat_postMessage.assert_not_called()


CONTENT = {"title": "No.1 案件", "introduction": "紹介", "pitch": "条件", "closing": "締め"}


@pytest.mark.parametrize("ids", [[], ["U1", "U2"], ["U1", "U1"]])
def test_preview_equals_send_and_empty_handlers_are_sent(ids):
    payload = {"case_id": "case", "announcement": CONTENT, "thread_text": "", "has_thread": False,
               "targets": [{"bp_id": "bp", "slack_channel_id": "C123", "handler_slack_ids": ids}]}
    preview, code = bot._preview_case_announcement(payload)
    c = MagicMock()
    c.chat_postMessage.return_value = {"ts": "123"}
    c.chat_getPermalink.return_value = {"permalink": "https://example.com"}
    result, _ = bot._process_case_announcement(c, payload)
    assert code == 200
    assert result["results"][0]["status"] == "sent"
    assert c.chat_postMessage.call_args.kwargs["text"] == preview["previews"][0]["text"]
    blocks = preview["previews"][0]["text"].split('\n\n')
    assert blocks[0] == "📢【新規案件のご案内】\nNo.1 案件"
    assert blocks[1] == (" ".join(f"<@{i}>" for i in dict.fromkeys(ids)) if ids else "紹介")


def test_bad_id_cannot_inject_mentions():
    with pytest.raises(ValueError):
        build_parent_text(CONTENT, None, None, bp_handler_ids=["U1> <!here"])
