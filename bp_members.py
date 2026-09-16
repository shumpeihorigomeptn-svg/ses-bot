"""BP担当者選択向けのSlack読取専用API。プロフィールは永続化しない。"""
import re
from flask import Blueprint, request


def handler_ids(value):
    """担当者IDの形式を検証し重複を除く。

    Args:
        value: JSON配列。省略時は空配列。
    Returns:
        SlackユーザーID一覧。不正な入力はValueError。
    """
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, str) or not re.fullmatch(r"[UW][A-Z0-9]+", v) for v in value):
        raise ValueError("担当者Slack IDの形式が不正です")
    return list(dict.fromkeys(value))


def user_summary(client, user_id, identity):
    """必要最小限の名前・所属判定だけを取り出す。

    Args:
        client: Slack WebClient。
        user_id: 参加者ID。
        identity: auth.testによる自社ワークスペース情報。
    Returns:
        表示名、自社・Bot判定、選択可否。
    """
    user = client.users_info(user=user_id)["user"]
    profile = user.get("profile") or {}
    enterprise = user.get("enterprise_user") or {}
    own = bool(user.get("team_id") == identity["team_id"] or identity["team_id"] in enterprise.get("teams", []) or (
        identity.get("enterprise_id") and identity["enterprise_id"] == enterprise.get("enterprise_id")
    ))
    bot = bool(user.get("is_bot") or user.get("is_app_user") or user_id == "USLACKBOT")
    known_team = bool(user.get("team_id") or enterprise.get("enterprise_id"))
    reason = "Bot（選択不可）" if bot else "自社メンバー（選択不可）" if own else "無効なユーザー（選択不可）" if user.get("deleted") else "所属を確認できません" if not known_team else ""
    return {"id": user_id, "display_name": profile.get("display_name") or profile.get("real_name") or user.get("real_name") or user.get("name") or user_id,
            "is_bot": bot, "is_own": own, "selectable": not bool(reason), "reason": reason}


def channel_members(client, channel_id):
    """ページングされた全参加者を読み、選択候補を返す。

    Args:
        client: Slack WebClient。
        channel_id: 対象チャンネル。
    Returns:
        参加者の表示情報一覧。途中失敗は全体の取得失敗として扱う。
    """
    if not isinstance(channel_id, str) or not re.fullmatch(r"[CG][A-Z0-9]+", channel_id):
        raise ValueError("SlackチャンネルIDを確認してください")
    identity = client.auth_test()
    if not identity.get("team_id"):
        raise RuntimeError("自社ワークスペースを確認できません")
    ids, cursor, seen = [], "", set()
    while True:
        page = client.conversations_members(channel=channel_id, limit=200, cursor=cursor)
        ids.extend(page["members"])
        cursor = (page.get("response_metadata") or {}).get("next_cursor", "").strip()
        if not cursor:
            break
        if cursor in seen:
            raise RuntimeError("参加者一覧のページングに失敗しました")
        seen.add(cursor)
    return [user_summary(client, uid, identity) for uid in dict.fromkeys(ids)]


def resolve_users(client, ids):
    """登録済み担当者の名前を取得し、失敗分はIDで返す。

    Args:
        client: Slack WebClient。
        ids: 保存済みSlack ID一覧。
    Returns:
        ユーザー表示情報。チャンネル参加者取得は呼ばない。
    """
    users = []
    for uid in handler_ids(ids):
        try:
            user = client.users_info(user=uid)["user"]
            profile = user.get("profile") or {}
            name = profile.get("display_name") or profile.get("real_name") or user.get("real_name") or user.get("name") or uid
            users.append({"id": uid, "display_name": name, "resolved": True})
        except Exception:
            users.append({"id": uid, "display_name": uid, "resolved": False})
    return users


def create_bp_members_blueprint(client):
    """既存Bot HTTPサーバーに読取専用エンドポイントを追加する。

    Args:
        client: Botの認証済みSlackクライアント。
    Returns:
        登録用Flask Blueprint。
    """
    blueprint = Blueprint("bp_members", __name__)

    @blueprint.get("/bp-members")
    def members():
        """Args: query.channel_id。Returns: 参加者一覧または取得エラー。"""
        try:
            return {"members": channel_members(client, request.args.get("channel_id"))}
        except ValueError as exc:
            return {"error": str(exc)}, 400
        except Exception:
            return {"error": "Slack参加者を取得できませんでした。権限・チャンネル参加状況を確認して再取得してください。"}, 502

    @blueprint.post("/bp-users")
    def users():
        """Args: JSON.user_ids。Returns: 登録IDの表示名一覧。"""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return {"error": "JSONオブジェクトが必要です"}, 400
        try:
            return {"users": resolve_users(client, data.get("user_ids"))}
        except ValueError as exc:
            return {"error": str(exc)}, 400

    return blueprint
