"""文档指纹：解密后的原文经 Unicode NFC 规范化后计算 SHA-256。

同一份合同文本若只是 Unicode 组合形式不同（例如预组合的 ``é`` 与
``e`` + 组合重音符号），NFC 之后字节序列一致，指纹也一致。
指纹为不可逆摘要，可直接落库 / 出参；原文仍只以密文存储。
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata

__all__ = ["normalized_fingerprint", "encode_cursor", "decode_cursor"]


def normalized_fingerprint(text: str) -> str:
    """返回 ``SHA-256(NFC(text).encode('utf-8'))`` 的十六进制摘要。"""
    normalized = unicodedata.normalize("NFC", text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---- 稳定分页游标：不透明 base64url（无填充）包裹 JSON，内容为 (created_at, id) ----


def encode_cursor(created_at: str, document_id: str) -> str:
    raw = json.dumps([created_at, document_id], separators=(",", ":")).encode("utf-8")
    # 去掉 "=" 填充，游标可直接放进 query string，无需百分号编码
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str) -> tuple[str, str]:
    """解析游标；格式非法时抛 ``ValueError``（由服务层映射为 400）。"""
    try:
        padded = cursor.encode("ascii") + b"=" * (-len(cursor) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")
        payload = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("非法分页游标") from exc
    if (
        not isinstance(payload, list)
        or len(payload) != 2
        or not all(isinstance(v, str) for v in payload)
        or not all(payload)
    ):
        raise ValueError("非法分页游标")
    return payload[0], payload[1]
