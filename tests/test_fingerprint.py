"""指纹与分页游标的纯函数测试。"""
import hashlib
import unicodedata

import pytest

from app.fingerprint import decode_cursor, encode_cursor, normalized_fingerprint


def test_fingerprint_is_sha256_of_nfc_utf8():
    text = "合同café🎉"
    expected = hashlib.sha256(
        unicodedata.normalize("NFC", text).encode("utf-8")
    ).hexdigest()
    assert normalized_fingerprint(text) == expected
    assert len(normalized_fingerprint(text)) == 64


def test_nfd_and_nfc_have_same_fingerprint():
    base = "café 合同 ①"
    nfd = unicodedata.normalize("NFD", base)
    nfc = unicodedata.normalize("NFC", base)
    assert nfd != nfc  # 码位序列确实不同
    assert normalized_fingerprint(nfd) == normalized_fingerprint(nfc)


def test_different_texts_differ():
    assert normalized_fingerprint("合同甲") != normalized_fingerprint("合同乙")


def test_cursor_roundtrip():
    cursor = encode_cursor("2026-09-22T08:30:00.000000Z", "abc123")
    created_at, doc_id = decode_cursor(cursor)
    assert created_at == "2026-09-22T08:30:00.000000Z"
    assert doc_id == "abc123"


def test_cursor_is_printable_and_urlsafe():
    cursor = encode_cursor("2026-09-22T08:30:00.000000Z", "id|with|pipes")
    assert all(c.isalnum() or c in "-_=" for c in cursor)
    # 内部含 | 分隔符也能正确切分（rsplit 仅切一次）
    assert decode_cursor(cursor) == ("2026-09-22T08:30:00.000000Z", "id|with|pipes")


@pytest.mark.parametrize("bad", ["", "%%%", "not-base64!!!", "YWJj", "abc|"])
def test_bad_cursor_rejected(bad):
    with pytest.raises(ValueError):
        decode_cursor(bad)
