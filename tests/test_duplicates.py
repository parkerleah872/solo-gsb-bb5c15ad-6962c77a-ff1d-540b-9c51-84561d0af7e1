"""重复检测接口：NFC 规范化指纹、exact_normalized 匹配、稳定分页与旧数据回填。"""
import hashlib
import sqlite3
import unicodedata

import aiosqlite
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.crypto import CryptoBox
from app.fingerprint import normalized_fingerprint
from app.main import app

pytestmark = pytest.mark.asyncio


def _body(text, category="PERSON", start=0, end=1):
    return {
        "text": text,
        "spans": [
            {"start": start, "end": end, "priority": 1, "category": category}
        ],
    }


async def _submit(client, text, start=0, end=1, category="PERSON"):
    resp = await client.post(
        "/documents", json=_body(text, category=category, start=start, end=end)
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["document_id"]


async def test_exact_duplicates_found_and_self_excluded(client):
    text = "甲方张三向乙方李四借款人民币10000元。"
    id_a = await _submit(client, text, start=2, end=4, category="PERSON")
    id_b = await _submit(client, text, start=2, end=4, category="PERSON")
    # 仅部分内容相同的文档不算重复
    await _submit(client, text + "补充条款", start=2, end=4, category="PERSON")

    resp = await client.post(f"/documents/{id_a}/duplicates")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["document_id"] == id_a
    assert data["fingerprint"] == normalized_fingerprint(text)
    assert len(data["matches"]) == 1
    match = data["matches"][0]
    assert match["document_id"] == id_b
    assert match["fingerprint"] == data["fingerprint"]
    assert match["match_type"] == "exact_normalized"
    assert "created_at" in match
    assert data["next_cursor"] is None

    # 响应绝不包含原文 / 脱敏文本 / 占位符
    assert "redacted_text" not in data
    assert "fragments" not in data
    assert set(match.keys()) == {"document_id", "fingerprint", "created_at", "match_type"}
    assert "张三" not in resp.text
    assert "{{" not in resp.text


async def test_nfc_normalization_matches_equivalent_unicode(client):
    nfd = unicodedata.normalize("NFD", "合同café甲方")
    nfc = unicodedata.normalize("NFC", "合同café甲方")
    assert nfd != nfc  # 前提：原始码位序列确实不同

    id_nfc = await _submit(client, nfc, end=2)
    id_nfd = await _submit(client, nfd, end=2)

    resp = await client.post(f"/documents/{id_nfc}/duplicates")
    assert resp.status_code == 200, resp.text
    ids = [m["document_id"] for m in resp.json()["matches"]]
    assert ids == [id_nfd]

    expected = hashlib.sha256(
        unicodedata.normalize("NFC", nfc).encode("utf-8")
    ).hexdigest()
    assert resp.json()["fingerprint"] == expected


async def test_missing_document_404(client):
    resp = await client.post("/documents/" + "0" * 32 + "/duplicates")
    assert resp.status_code == 404


async def test_expired_document_410(settings):
    settings.default_ttl = 1
    import asyncio

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            text = "甲方张三。"
            doc_id = await _submit(client, text, start=2, end=4, category="PERSON")
            await asyncio.sleep(1.1)
            resp = await client.post(f"/documents/{doc_id}/duplicates")
            assert resp.status_code == 410
    get_settings.cache_clear()


async def test_pagination_stable_by_created_then_id(client):
    text = "完全相同的合同正文内容XYZ"
    ids = [await _submit(client, text, end=2, category="ORG") for _ in range(5)]

    # 首页 2 条，顺序与提交顺序一致（created_at 升序；同刻再按 id 决胜）
    r1 = await client.post(f"/documents/{ids[0]}/duplicates?limit=2")
    assert r1.status_code == 200, r1.text
    page1 = r1.json()
    assert [m["document_id"] for m in page1["matches"]] == ids[1:3]
    assert page1["next_cursor"]

    # 逐页翻完，顺序稳定且不重不漏；首页目标文档自身被排除
    seen = [m["document_id"] for m in page1["matches"]]
    cursor = page1["next_cursor"]
    while cursor:
        r = await client.post(
            f"/documents/{ids[0]}/duplicates?limit=2&cursor={cursor}"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        seen.extend(m["document_id"] for m in body["matches"])
        cursor = body["next_cursor"]

    assert seen == ids[1:]
    assert len(set(seen)) == len(seen)

    # 以最后一份文档为目标时，其余 4 份都应命中（含排在它之前的文档）
    r_last = await client.post(f"/documents/{ids[-1]}/duplicates?limit=10")
    assert {m["document_id"] for m in r_last.json()["matches"]} == set(ids[:-1])


async def test_invalid_cursor_400(client):
    doc_id = await _submit(client, "abc甲方", end=2, category="ORG")
    resp = await client.post(f"/documents/{doc_id}/duplicates?cursor=%%%not-base64")
    assert resp.status_code == 400


async def test_limit_validation(client):
    doc_id = await _submit(client, "abc甲方", end=2, category="ORG")
    assert (await client.post(f"/documents/{doc_id}/duplicates?limit=0")).status_code == 422
    assert (
        await client.post(f"/documents/{doc_id}/duplicates?limit=201")
    ).status_code == 422


# ---------- 旧数据迁移 + 指纹回填 ----------


_OLD_SCHEMA = """
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    redacted TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_id TEXT
);
CREATE TABLE policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE policy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL, category TEXT NOT NULL, pattern TEXT NOT NULL,
    priority INTEGER NOT NULL, ordinal INTEGER NOT NULL,
    UNIQUE(policy_id, rule_id)
);
CREATE TABLE fragments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    fragment_id INTEGER NOT NULL, decision_rank INTEGER NOT NULL,
    blocked_by_fragment_id INTEGER,
    placeholder TEXT NOT NULL, category TEXT NOT NULL,
    start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL,
    priority INTEGER NOT NULL, kept INTEGER NOT NULL, drop_reason TEXT,
    cipher_value BLOB, source TEXT NOT NULL DEFAULT 'manual', rule_id TEXT
);
CREATE TABLE restore_tokens (
    token_hash TEXT PRIMARY KEY, document_id TEXT NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
"""


async def test_legacy_db_migration_and_startup_backfill(settings):
    db_path = settings.db_path
    crypto = CryptoBox("test-master-key")
    text = "旧库中的合同原文ABC"
    expires = "2099-01-01T00:00:00.000000Z"

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_OLD_SCHEMA)
        conn.execute(
            "INSERT INTO documents (id, ciphertext, redacted, expires_at, policy_id)"
            " VALUES (?, ?, ?, ?, ?)",
            ("legacy1", crypto.encrypt(text), "redacted", expires, None),
        )
        conn.commit()
    finally:
        conn.close()

    # 启动 lifespan 即完成幂等迁移与旧行指纹回填
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # 新提交一份同文文档，应当能通过旧文档的指纹命中
            new_id = await _submit(client, text, end=2, category="ORG")
            resp = await client.post("/documents/{n}/duplicates".format(n=new_id))
            assert resp.status_code == 200, resp.text
            matches = resp.json()["matches"]
            assert [m["document_id"] for m in matches] == ["legacy1"]
            assert matches[0]["fingerprint"] == normalized_fingerprint(text)
            assert matches[0]["match_type"] == "exact_normalized"

    get_settings.cache_clear()

    # 迁移后列与索引都已就位
    async with aiosqlite.connect(db_path) as db:
        cols = {r[1] for r in await db.execute_fetchall("PRAGMA table_info(documents)")}
        assert {"created_at", "fingerprint"} <= cols
        indexes = {
            r[1] for r in await db.execute_fetchall("PRAGMA index_list(documents)")
        }
        assert "idx_documents_fingerprint" in indexes


async def test_lazy_backfill_of_null_fingerprint_row(settings):
    """迁移后仍为 NULL 指纹的旧行：重复检测访问时按需解密回填，不重启即可命中。"""
    db_path = settings.db_path
    expires = "2099-01-01T00:00:00.000000Z"
    text = "按需回填的合同正文内容GHI"

    # 先经一次空启动拿到迁移后的新表结构，再以“旧行”身份插入 NULL 指纹数据。
    # 不清除 settings 缓存（否则第二次 lifespan 会回退到默认的 /data 路径）。
    async with LifespanManager(app):
        pass

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO documents (id, ciphertext, redacted, created_at,"
            " expires_at, fingerprint, policy_id)"
            " VALUES (?, ?, ?, ?, ?, NULL, ?)",
            ("legacy-lazy", CryptoBox("test-master-key").encrypt(text), "r",
             "2098-01-01T00:00:00.000000Z", expires, None),
        )
        conn.commit()
    finally:
        conn.close()

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            new_id = await _submit(client, text, end=2, category="ORG")
            # 查旧行 -> 触发按需回填
            resp = await client.post("/documents/legacy-lazy/duplicates")
            assert resp.status_code == 200, resp.text
            assert [m["document_id"] for m in resp.json()["matches"]] == [new_id]

            # 新文档视角同样能查到已回填的旧行
            resp2 = await client.post(f"/documents/{new_id}/duplicates")
            assert [m["document_id"] for m in resp2.json()["matches"]] == [
                "legacy-lazy"
            ]
    get_settings.cache_clear()


async def test_undecryptable_legacy_row_returns_500_without_leak(settings):
    """旧行密文无法解密（如主密钥已轮换）：启动回填跳过，按需回填返回 500 且不泄露。"""
    db_path = settings.db_path
    expires = "2099-01-01T00:00:00.000000Z"
    text = "无法解密的合同正文内容JKL"

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_OLD_SCHEMA)
        conn.execute(
            "INSERT INTO documents (id, ciphertext, redacted, expires_at, policy_id)"
            " VALUES (?, ?, ?, ?, ?)",
            ("legacy-x", CryptoBox("old-master-key").encrypt(text), "r", expires, None),
        )
        conn.commit()
    finally:
        conn.close()

    async with LifespanManager(app):
        # 启动回填跳过了无法解密的行：fingerprint 仍为 NULL
        async with aiosqlite.connect(db_path) as db:
            row = await db.execute_fetchall(
                "SELECT fingerprint FROM documents WHERE id = 'legacy-x'"
            )
        assert row[0][0] is None

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/documents/legacy-x/duplicates")
            assert resp.status_code == 500
            assert "JKL" not in resp.text
    get_settings.cache_clear()
