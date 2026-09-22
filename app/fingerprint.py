"""文档原文指纹：先做 Unicode NFC 规范化再计算 SHA-256。

重复检测不关心编码形式差异（同一文本可能以 NFC / NFD 等不同码位序列存储），
因此统一规范化后再哈希；指纹本身不含任何原文信息，可安全建索引与返回。
"""
from __future__ import annotations

import hashlib
import unicodedata


def normalize_text(text: str) -> str:
    """重复检测使用的规范化原文（NFC）。"""
    return unicodedata.normalize("NFC", text)


def fingerprint_text(text: str) -> str:
    """返回 NFC 规范化原文的 SHA-256 十六进制摘要（64 字符）。"""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()
