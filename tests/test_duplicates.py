"""重复检测测试：NFC 规范化指纹、未过期匹配、分页、旧库迁移回填、隐私边界。"""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import unicodedata
from datetime import timedelta

from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.crypto import CryptoBox
from app.db import LEGACY_CREATED_AT
from app.fingerprint import fingerprint_text, normalize_text
from app.main import app
from app.services.timeutil import to_iso, utcnow


def _span(start: int = 0, end: int = 1) -> dict:
    return {"start": start, "end": end, "priority": 1, "category": "x"}


async def _submit(client, text, ttl=None):
    body = {"text": text, "spans": [_span(0, 1)]}
    if ttl is not None:
        body["ttl"] = ttl
    resp = await client.post("/documents", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------- 指纹纯函数 ----------


def test_fingerprint_nfc_equivalence():
    nfc = "café"  # café
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd  # 码位序列确实不同
    assert normalize_text(nfd) == unicodedata.normalize("NFC", nfc)
    assert fingerprint_text(nfd) == fingerprint_text(nfc)


def test_fingerprint_is_sha256_of_nfc():
    text = "甲方张三"
    expected = hashlib.sha256(
        unicodedata.normalize("NFC", text).encode("utf-8")
    ).hexdigest()
    assert fingerprint_text(text) == expected
    assert len(fingerprint_text(text)) == 64


# ---------- API 端到端 ----------


async def test_duplicates_exact_match(client):
    text = "甲方张三向乙方李四借款人民币10000元。"
    first = await _submit(client, text)
    second = await _submit(client, text)  # 原文完全一致 -> 重复
    third = await _submit(client, "一份完全不同的合同文本XYZ。")

    resp = await client.post(f"/documents/{first['document_id']}/duplicates")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["document_id"] == first["document_id"]
    assert data["fingerprint"] == fingerprint_text(text)
    assert data["next_cursor"] is None

    ids = {m["document_id"] for m in data["matches"]}
    assert ids == {second["document_id"]}
    assert third["document_id"] not in ids
    # 不含自身
    assert first["document_id"] not in ids

    match = data["matches"][0]
    assert set(match.keys()) == {
        "document_id",
        "fingerprint",
        "created_at",
        "match_type",
    }
    assert match["match_type"] == "exact_normalized"
    assert match["fingerprint"] == data["fingerprint"]
    assert match["created_at"]

    # 反向检测结果对称
    resp2 = await client.post(f"/documents/{second['document_id']}/duplicates")
    assert {m["document_id"] for m in resp2.json()["matches"]} == {
        first["document_id"]
    }


async def test_duplicates_match_across_unicode_normalization_forms(client):
    text = "A" + unicodedata.normalize("NFC", "é") + "B合同"
    nfc_doc = await _submit(client, text)
    nfd_doc = await _submit(client, unicodedata.normalize("NFD", text))

    resp = await client.post(f"/documents/{nfc_doc['document_id']}/duplicates")
    assert resp.status_code == 200
    ids = {m["document_id"] for m in resp.json()["matches"]}
    assert ids == {nfd_doc["document_id"]}


async def test_duplicates_response_never_leaks_plaintext_or_placeholders(client):
    secret = "机密合同正文：北京某某科技有限公司"
    d1 = await _submit(client, secret)
    d2 = await _submit(client, secret)

    resp = await client.post(f"/documents/{d1['document_id']}/duplicates")
    raw = resp.text
    # 响应原文中不出现敏感内容、占位符或脱敏文本
    assert "机密" not in raw
    assert "北京某某科技" not in raw
    assert "{{" not in raw
    assert "redacted" not in raw
    # d2 的恢复令牌也不在响应中
    assert d2["restore_token"] not in raw


async def test_duplicates_excludes_expired_documents(settings):
    settings.default_ttl = 3600
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            text = "待过期的重复合同文本。"
            live = await _submit(client, text, ttl=3600)
            short = await _submit(client, text, ttl=1)

            await asyncio.sleep(1.1)

            # 过期文档不参与匹配
            resp = await client.post(f"/documents/{live['document_id']}/duplicates")
            assert resp.status_code == 200
            assert [m["document_id"] for m in resp.json()["matches"]] == []

            # 检测目标本身已过期 -> 410
            gone = await client.post(f"/documents/{short['document_id']}/duplicates")
            assert gone.status_code == 410
    get_settings.cache_clear()


async def test_duplicates_unknown_document_404(client):
    resp = await client.post("/documents/" + "f" * 32 + "/duplicates")
    assert resp.status_code == 404


async def test_duplicates_invalid_limit_422(client):
    data = await _submit(client, "限量参数校验文本。")
    resp = await client.post(
        f"/documents/{data['document_id']}/duplicates?limit=0"
    )
    assert resp.status_code == 422
    resp = await client.post(
        f"/documents/{data['document_id']}/duplicates?limit=101"
    )
    assert resp.status_code == 422


async def test_duplicates_invalid_cursor_400(client):
    data = await _submit(client, "游标校验文本。")
    resp = await client.post(
        f"/documents/{data['document_id']}/duplicates?cursor=%%%not-base64"
    )
    assert resp.status_code == 400


async def test_duplicates_pagination_stable(client):
    text = "分页稳定性基准合同文本。"
    # 最先提交被检测文档，再提交 6 个重复文档
    target = (await _submit(client, text))["document_id"]
    others = [(await _submit(client, text))["document_id"] for _ in range(6)]

    def _page(cursor):
        url = f"/documents/{target}/duplicates?limit=2"
        if cursor:
            url += f"&cursor={cursor}"
        return client.post(url)

    seen: list[str] = []
    cursor = None
    for page_no in range(3):
        resp = await _page(cursor)
        assert resp.status_code == 200, resp.text
        page = resp.json()
        assert len(page["matches"]) == 2
        seen.extend(m["document_id"] for m in page["matches"])
        cursor = page["next_cursor"]
        if page_no < 2:
            assert cursor
        else:
            assert cursor is None  # 6 条 / 每页 2 条 -> 恰好 3 页

    # 不重不漏
    assert sorted(seen) == sorted(others)
    assert len(seen) == len(set(seen))

    # 顺序与服务端 (created_at ASC, id ASC) 一致
    ordered = await _ordered_duplicate_ids(client, target)
    assert seen == ordered


async def _ordered_duplicate_ids(client, target_id):
    from app.main import app as _app

    db = _app.state.service.db
    async with db.execute(
        "SELECT id FROM documents WHERE id != ? ORDER BY created_at ASC, id ASC",
        (target_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [r["id"] for r in rows]


# ---------- 旧库迁移 + 指纹回填 ----------


def _build_legacy_db(path: str, master_key: str) -> tuple[str, str]:
    """手工构造「指纹功能上线前」的旧库：documents 无 fingerprint / created_at 列，
    并写入一条旧文档。返回 (legacy_doc_id, plaintext)。"""
    crypto = CryptoBox(master_key)
    plaintext = "旧库迁移合同：A" + unicodedata.normalize("NFD", "é") + "B公司"
    doc_id = "a" * 32
    # 旧 schema（与本功能上线前的 documents 表保持一致）
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "CREATE TABLE documents ("
            " id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, redacted TEXT NOT NULL,"
            " expires_at TEXT NOT NULL, policy_id TEXT)"
        )
        conn.execute(
            "CREATE TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
            " created_at TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE policy_rules (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
            " rule_id TEXT NOT NULL, category TEXT NOT NULL, pattern TEXT NOT NULL,"
            " priority INTEGER NOT NULL, ordinal INTEGER NOT NULL,"
            " UNIQUE(policy_id, rule_id))"
        )
        conn.execute(
            "CREATE TABLE fragments (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
            " fragment_id INTEGER, decision_rank INTEGER, blocked_by_fragment_id INTEGER,"
            " placeholder TEXT NOT NULL, category TEXT NOT NULL,"
            " start_offset INTEGER NOT NULL, end_offset INTEGER NOT NULL,"
            " priority INTEGER NOT NULL, kept INTEGER NOT NULL, drop_reason TEXT,"
            " cipher_value BLOB, source TEXT NOT NULL DEFAULT 'manual', rule_id TEXT)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX idx_fragments_fragment_id"
            " ON fragments(document_id, fragment_id)"
        )
        conn.execute(
            "CREATE TABLE restore_tokens (token_hash TEXT PRIMARY KEY,"
            " document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,"
            " expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO documents (id, ciphertext, redacted, expires_at, policy_id)"
            " VALUES (?, ?, ?, ?, NULL)",
            (
                doc_id,
                crypto.encrypt(plaintext),
                "{{X:01}}",
                to_iso(utcnow() + timedelta(hours=1)),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return doc_id, plaintext


async def test_legacy_db_migration_backfill_and_match(settings, tmp_path):
    db_file = tmp_path / "legacy.db"
    legacy_id, plaintext = _build_legacy_db(str(db_file), settings.master_key)
    settings.database_url = f"sqlite:///{db_file}"

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # lifespan 已完成迁移 + 启动回填：旧文档指纹已就位
            service = app.state.service
            async with service.db.execute(
                "SELECT fingerprint, created_at FROM documents WHERE id = ?",
                (legacy_id,),
            ) as cur:
                row = await cur.fetchone()
            assert row["fingerprint"] == fingerprint_text(plaintext)
            assert row["created_at"] == LEGACY_CREATED_AT

            # 新提交一份 NFC 形式不同但规范化后相同的文档，应与旧文档互相命中
            new = await _submit(client, unicodedata.normalize("NFC", plaintext))

            resp = await client.post(f"/documents/{new['document_id']}/duplicates")
            assert resp.status_code == 200, resp.text
            ids = {m["document_id"] for m in resp.json()["matches"]}
            assert ids == {legacy_id}
            m = resp.json()["matches"][0]
            assert m["match_type"] == "exact_normalized"
            assert m["created_at"].startswith("1970-01-01")

            # 以旧文档为目标同样能命中新文档
            resp2 = await client.post(f"/documents/{legacy_id}/duplicates")
            assert {m["document_id"] for m in resp2.json()["matches"]} == {
                new["document_id"]
            }
    get_settings.cache_clear()


async def test_backfill_idempotent_on_restart(settings, tmp_path, monkeypatch):
    db_file = tmp_path / "twice.db"
    settings.database_url = f"sqlite:///{db_file}"
    # 第二次进入 lifespan 会重新调用 get_settings()，需用环境变量持久化配置
    monkeypatch.setenv("REDACT_DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("REDACT_MASTER_KEY", settings.master_key)
    monkeypatch.setenv("REDACT_ENV", "test")

    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            await _submit(client, "重复启动回填幂等文本。")
    get_settings.cache_clear()

    # 第二次启动：所有行已有指纹，回填数应为 0 且不报错
    async with LifespanManager(app):
        count = await app.state.service.backfill_fingerprints()
        assert count == 0
    get_settings.cache_clear()
