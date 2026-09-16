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


def build_parent_text(announcement: dict[str, str], mention_id: str | None, sheet_url: Any) -> str:
    """5ブロックの間に空行を入れ、見出しラベルの直後を改行する。

    Args:
        announcement: title、introduction、pitch、closing。
        mention_id: Speee担当ID。未解決時は問い合わせ行を省略する。
        sheet_url: BPごとのシートURL。未設定・不正時は省略する。
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
        links.append(f"📄 案件紹介シート: <{url}|貴社向け案件一覧>")
    links.append("💬 案件詳細は本投稿のスレッドをご覧ください。")
    closing = [announcement["closing"].strip()]
    if mention_id:
        closing.append(f"ご不明点は <@{mention_id}> までお願いします。")
    blocks = [
        "📢【新規案件のご案内】\n" + announcement["title"].strip(),
        announcement["introduction"].strip(),
        announcement["pitch"].strip(),
        "\n".join(links),
        "\n".join(line for line in closing if line),
    ]
    return "\n\n".join(block for block in blocks if block)
