"""BPディレクトリ専用の短時間リクエスト署名（API/Botで同一仕様）。"""
import hashlib
import hmac


def sign_directory_request(secret: str, timestamp: str, method: str, target: str, body: bytes) -> str:
    """用途・時刻・HTTP要求を結び付け、共有鍵そのものは送信しない。

    Args:
        secret: 両サービスの共有署名鍵。
        timestamp: UNIX時刻（秒）。
        method: HTTPメソッド。
        target: パスとクエリ文字列。
        body: 送信する生のボディ。
    Returns:
        HMAC-SHA256の16進署名。JWTと用途を分離する。
    """
    message = '\n'.join(['bp-directory-v1', timestamp, method, target, hashlib.sha256(body).hexdigest()])
    return hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
