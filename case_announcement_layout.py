"""案件案内の固定テンプレート（送信・プレビュー共通）。"""
from typing import Any
from urllib.parse import urlparse


def validate_announcement(value: Any) -> bool:
    """必要な文字列ブロックが揃っているか判定する。

    Args:
        value: APIから受け取った構造化本文。
    Returns:
        見出し・紹介文・ピッチが非空で、締め文も文字列ならTrue。
    """
    return isinstance(value, dict) and all(
        isinstance(value.get(key), str) and (key == "closing" or bool(value[key].strip()))
        for key in ("title", "introduction", "pitch", "closing")
    )


def _plain_block(value: str) -> str:
    """空行をブロック境界に限定し、Slack制御文字を文字として表示する。

    Args:
        value: 検証済み編集ブロック。
    Returns:
        空行を除去し & < > のみをエスケープした文字列。
    """
    text = "\n".join(line.strip() for line in value.splitlines() if line.strip())
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_parent_text(announcement: dict[str, str], mention_id: str | None, sheet_url: Any, *, has_thread: bool = True) -> str:
    """5ブロックの間に空行を入れ、見出しラベルの直後を改行する。

    Args:
        announcement: 検証済みのtitle、introduction、pitch、closing（空可）。
        mention_id: Speee担当ID。未解決時は問い合わせ行を省略する。
        sheet_url: BPごとのシートURL。未設定・不正時は省略する。
        has_thread: スレッド返信がある場合だけ誘導行を表示する。
    Returns:
        完成したSlack本文。
    """
    url = sheet_url.strip() if isinstance(sheet_url, str) else ""
    links = []
    try:
        parsed = urlparse(url)
        safe_url = parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except ValueError:
        safe_url = False
    if safe_url and not any(c in url for c in "<>|\n\r"):
        escaped_url = url.replace("&", "&amp;")
        links.append(f"📄 案件紹介シート: <{escaped_url}|貴社向け案件一覧>")
    if has_thread:
        links.append("💬 案件詳細は本投稿のスレッドをご覧ください。")
    closing = [_plain_block(announcement["closing"])]
    if mention_id:
        closing.append(f"ご不明点は <@{mention_id}> までお願いします。")
    blocks = [
        "📢【新規案件のご案内】\n" + _plain_block(announcement["title"]),
        _plain_block(announcement["introduction"]),
        _plain_block(announcement["pitch"]),
        "\n".join(links),
        "\n".join(line for line in closing if line),
    ]
    return "\n\n".join(block for block in blocks if block)
