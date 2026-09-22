"""文档脱敏、查询、恢复的业务逻辑。"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta

import aiosqlite

from cryptography.fernet import InvalidToken

from app.crypto import CryptoBox, random_token
from app.fingerprint import (
    decode_cursor,
    encode_cursor,
    normalized_fingerprint,
)
from app.policy_engine import ProcessRuleRunner, apply_rules, compile_rules
from app.redaction import (
    AUTO,
    PLACEHOLDER_PATTERN,
    InputSpan,
    redact,
    validate_category,
)
from app.schemas import (
    FragmentOut,
    MAX_DUPLICATE_LIMIT,
    MAX_SPANS,
    RestoreBatchItem,
    RestoredItem,
    RestoredOccurrence,
    SubmitRequest,
)
from app.services.errors import (
    ExpiredError,
    NotFoundError,
    ServiceError,
    UnauthorizedError,
)
from app.services.policy_service import PolicyService
from app.services.timeutil import from_iso, to_iso, utcnow


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


logger = logging.getLogger("redaction.documents")


class DocumentService:
    def __init__(
        self,
        db: aiosqlite.Connection,
        crypto: CryptoBox,
        default_ttl: int,
        max_ttl: int,
        token_ttl: int,
        policies: PolicyService,
        rule_timeout: float,
        rule_runner: ProcessRuleRunner,
    ) -> None:
        self.db = db
        self.crypto = crypto
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl
        self.token_ttl = token_ttl
        self.policies = policies
        self.rule_timeout = rule_timeout
        self.rule_runner = rule_runner

    # ---------- 提交脱敏 ----------

    async def submit(self, req: SubmitRequest) -> dict:
        ttl = req.ttl if req.ttl is not None else self.default_ttl
        if not 1 <= ttl <= self.max_ttl:
            raise ServiceError(f"ttl 必须在 1..{self.max_ttl} 秒之间", 422)

        if not req.spans and not req.policy_id:
            raise ServiceError("spans 与 policy_id 至少提供其一", 422)

        # 位置校验：必须落在原文内且非空区间
        for i, s in enumerate(req.spans):
            if not (0 <= s.start < s.end <= len(req.text)):
                raise ServiceError(
                    f"spans[{i}] 位置非法：需满足 0 <= start < end <= 文本长度"
                    f"（{len(req.text)}）",
                    422,
                )
            try:
                validate_category(s.category)
            except ValueError as exc:
                raise ServiceError(str(exc), 422) from exc

        # 人工片段先编号，自动片段追加其后；ordinal 仅用于稳定决胜
        inputs = [
            InputSpan(
                start=s.start,
                end=s.end,
                priority=s.priority,
                category=s.category,
                ordinal=i,
            )
            for i, s in enumerate(req.spans)
        ]

        if req.policy_id is not None:
            # 策略缺失 -> 404；规则非法 / 超时 / 空匹配 / 命中过多 -> 422，均不写文档
            specs = await self.policies.load_specs(req.policy_id)
            compiled = compile_rules(specs)
            # 自动片段数量与人工片段合并后不得超过片段上限
            auto_matches = await apply_rules(
                req.text,
                compiled,
                timeout=self.rule_timeout,
                max_matches=MAX_SPANS - len(inputs),
                runner=self.rule_runner,
            )
            base = len(inputs)
            for j, m in enumerate(auto_matches):
                inputs.append(
                    InputSpan(
                        start=m.start,
                        end=m.end,
                        priority=m.rule.priority,
                        category=m.rule.category,
                        ordinal=base + j,
                        source=AUTO,
                        rule_id=m.rule.rule_id,
                    )
                )

        result = redact(req.text, inputs)

        doc_id = uuid.uuid4().hex
        now = utcnow()
        doc_expires = now + timedelta(seconds=ttl)
        fingerprint = normalized_fingerprint(req.text)
        token = random_token()
        # 令牌有效期不超过文档映射本身
        token_expires = min(now + timedelta(seconds=self.token_ttl), doc_expires)

        async with self.db.cursor() as cur:
            await cur.execute(
                "INSERT INTO documents (id, ciphertext, redacted, created_at,"
                " expires_at, fingerprint, policy_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    doc_id,
                    self.crypto.encrypt(req.text),
                    result.redacted_text,
                    to_iso(now),
                    to_iso(doc_expires),
                    fingerprint,
                    req.policy_id,
                ),
            )
            await cur.executemany(
                "INSERT INTO fragments (document_id, fragment_id, decision_rank,"
                " blocked_by_fragment_id, placeholder, category,"
                " start_offset, end_offset, priority, kept, drop_reason, cipher_value,"
                " source, rule_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        doc_id,
                        sp.fragment_id,
                        sp.decision_rank,
                        sp.blocked_by_fragment_id,
                        sp.placeholder,
                        sp.category,
                        sp.start,
                        sp.end,
                        sp.priority,
                        int(sp.kept),
                        sp.drop_reason,
                        self.crypto.encrypt(sp.value) if sp.kept else None,
                        sp.source,
                        sp.rule_id,
                    )
                    for sp in result.spans
                ],
            )
            await cur.execute(
                "INSERT INTO restore_tokens (token_hash, document_id, expires_at, used)"
                " VALUES (?, ?, ?, 0)",
                (hash_token(token), doc_id, to_iso(token_expires)),
            )
            await self.db.commit()

        return {
            "document_id": doc_id,
            "redacted_text": result.redacted_text,
            "fragments": [self._fragment_out(sp) for sp in result.spans],
            "restore_token": token,
            "expires_at": doc_expires,
            "token_expires_at": token_expires,
        }

    # ---------- 查询脱敏结果 ----------

    async def get(self, document_id: str) -> dict:
        async with await self.db.execute(
            "SELECT id, redacted, expires_at FROM documents WHERE id = ?",
            (document_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise NotFoundError("文档不存在或已过期删除")
        expires = from_iso(row["expires_at"])
        if expires <= utcnow():
            await self._delete_document(document_id)
            await self.db.commit()
            raise ExpiredError("文档映射已过期")

        async with self.db.execute(
            "SELECT fragment_id, decision_rank, blocked_by_fragment_id,"
            " placeholder, category, start_offset, end_offset, priority,"
            " kept, drop_reason, source, rule_id FROM fragments WHERE document_id = ?"
            " ORDER BY fragment_id",
            (document_id,),
        ) as cur:
            frags = await cur.fetchall()
        return {
            "document_id": document_id,
            "redacted_text": row["redacted"],
            "fragments": [self._row_out(r) for r in frags],
            "expires_at": expires,
        }

    # ---------- 重复检测 ----------

    async def find_duplicates(
        self, document_id: str, limit: int, cursor: str | None
    ) -> dict:
        """查找其他未过期、NFC 规范化指纹相同的文档（exact_normalized）。

        结果只含文档 ID、指纹、创建时间与匹配类型，绝不返回原文或占位符；
        按 (created_at, id) 升序做 keyset 分页，翻页顺序稳定。
        """
        now = utcnow()
        now_iso = to_iso(now)

        async with self.db.execute(
            "SELECT id, ciphertext, fingerprint, expires_at FROM documents WHERE id = ?",
            (document_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise NotFoundError("文档不存在或已过期删除")
        if from_iso(row["expires_at"]) <= now:
            await self._delete_document(document_id)
            await self.db.commit()
            raise ExpiredError("文档映射已过期")

        fingerprint = row["fingerprint"]
        if fingerprint is None:
            # 旧数据：迁移只补了列，按需解密原文补算，回填后后续查询直接走索引
            fingerprint = await self._backfill_one(row)

        after_created = after_id = None
        if cursor is not None:
            try:
                after_created, after_id = decode_cursor(cursor)
            except ValueError as exc:
                raise ServiceError(str(exc), 400) from exc

        sql = (
            "SELECT id, fingerprint, created_at FROM documents"
            " WHERE fingerprint = ? AND expires_at > ? AND id <> ?"
        )
        params: list = [fingerprint, now_iso, document_id]
        if cursor is not None:
            sql += " AND (created_at > ? OR (created_at = ? AND id > ?))"
            params.extend([after_created, after_created, after_id])
        sql += " ORDER BY created_at ASC, id ASC LIMIT ?"
        params.append(limit + 1)  # 多取一条判断是否还有下一页

        async with self.db.execute(sql, params) as cur:
            rows = await cur.fetchall()

        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = None
        if has_more and page:
            next_cursor = encode_cursor(page[-1]["created_at"], page[-1]["id"])

        return {
            "document_id": document_id,
            "fingerprint": fingerprint,
            "matches": [
                {
                    "document_id": r["id"],
                    "fingerprint": r["fingerprint"],
                    "created_at": from_iso(r["created_at"]),
                    "match_type": "exact_normalized",
                }
                for r in page
            ],
            "next_cursor": next_cursor,
        }

    async def _backfill_one(self, row: aiosqlite.Row) -> str:
        """解密单个旧文档原文补算指纹并落库；密文无法解密时抛 500。"""
        try:
            plaintext = self.crypto.decrypt(row["ciphertext"])
        except InvalidToken as exc:
            raise ServiceError("文档原文无法解密，指纹回填失败", 500) from exc
        fingerprint = normalized_fingerprint(plaintext)
        await self.db.execute(
            "UPDATE documents SET fingerprint = ? WHERE id = ? AND fingerprint IS NULL",
            (fingerprint, row["id"]),
        )
        await self.db.commit()
        return fingerprint

    async def backfill_fingerprints(self, batch_size: int = 500) -> int:
        """启动回填：为旧数据（fingerprint 为 NULL）分批解密原文补算指纹。

        返回本次回填行数。按 id 做 keyset 遍历，每行恰好访问一次：无法解密的行
        （如主密钥已轮换）跳过并记录日志，不阻断启动；这类文档在被重复检测
        访问时还会触发一次按需回填。
        """
        total = 0
        last_id = ""
        while True:
            async with self.db.execute(
                "SELECT id, ciphertext FROM documents"
                " WHERE fingerprint IS NULL AND id > ? ORDER BY id LIMIT ?",
                (last_id, batch_size),
            ) as cur:
                rows = await cur.fetchall()
            if not rows:
                break
            last_id = rows[-1]["id"]
            for r in rows:
                try:
                    plaintext = self.crypto.decrypt(r["ciphertext"])
                except InvalidToken:
                    logger.warning("文档 %s 指纹回填跳过：密文无法解密", r["id"])
                    continue
                fp = normalized_fingerprint(plaintext)
                await self.db.execute(
                    "UPDATE documents SET fingerprint = ?"
                    " WHERE id = ? AND fingerprint IS NULL",
                    (fp, r["id"]),
                )
                total += 1
            await self.db.commit()
        if total:
            logger.info("旧文档指纹回填完成：%d 行", total)
        return total

    # ---------- 一次性令牌恢复 ----------

    async def restore(self, token: str, placeholders: list[str]) -> dict:
        wanted = self._dedup(placeholders)
        now = utcnow()

        async with self.db.cursor() as cur:
            # 单事务内完成：校验一次性令牌 -> 读出片段 -> 旧令牌作废 -> 轮换新令牌
            await cur.execute("BEGIN IMMEDIATE")
            await cur.execute(
                "SELECT document_id, expires_at, used FROM restore_tokens"
                " WHERE token_hash = ?",
                (hash_token(token),),
            )
            token_row = await cur.fetchone()
            if token_row is None:
                await cur.execute("ROLLBACK")
                raise UnauthorizedError("恢复令牌无效（可能已被使用）")
            if token_row["used"]:
                await cur.execute("ROLLBACK")
                raise UnauthorizedError("恢复令牌已使用")
            if from_iso(token_row["expires_at"]) <= now:
                await cur.execute(
                    "DELETE FROM restore_tokens WHERE token_hash = ?",
                    (hash_token(token),),
                )
                await cur.execute("COMMIT")
                raise UnauthorizedError("恢复令牌已过期，请重新提交文档")

            doc_id = token_row["document_id"]
            await cur.execute("SELECT expires_at FROM documents WHERE id = ?", (doc_id,))
            doc_row = await cur.fetchone()
            if doc_row is None or from_iso(doc_row["expires_at"]) <= now:
                await cur.execute("ROLLBACK")
                raise ExpiredError("文档映射已过期，无法恢复")
            doc_expires = from_iso(doc_row["expires_at"])

            await cur.execute(
                "SELECT placeholder, category, start_offset, end_offset, priority,"
                " cipher_value, source, rule_id FROM fragments"
                " WHERE document_id = ? AND kept = 1 ORDER BY start_offset",
                (doc_id,),
            )
            frag_rows = await cur.fetchall()

            by_placeholder: dict[str, list[aiosqlite.Row]] = {}
            for r in frag_rows:
                by_placeholder.setdefault(r["placeholder"], []).append(r)

            unknown = [p for p in wanted if p not in by_placeholder]
            if unknown:
                await cur.execute("ROLLBACK")
                raise ServiceError(f"占位符不属于该文档：{unknown}", 400)

            restored: list[RestoredItem] = []
            for p in wanted:
                rows = by_placeholder[p]
                restored.append(
                    RestoredItem(
                        placeholder=p,
                        category=rows[0]["category"],
                        value=self.crypto.decrypt(rows[0]["cipher_value"]),
                        occurrences=[
                            RestoredOccurrence(
                                start=r["start_offset"],
                                end=r["end_offset"],
                                priority=r["priority"],
                                source=r["source"],
                                rule_id=r["rule_id"],
                            )
                            for r in rows
                        ],
                    )
                )

            new_token = random_token()
            new_expires = min(now + timedelta(seconds=self.token_ttl), doc_expires)
            await cur.execute(
                "UPDATE restore_tokens SET used = 1 WHERE token_hash = ?",
                (hash_token(token),),
            )
            await cur.execute(
                "INSERT INTO restore_tokens (token_hash, document_id, expires_at, used)"
                " VALUES (?, ?, ?, 0)",
                (hash_token(new_token), doc_id, to_iso(new_expires)),
            )
            await cur.execute("COMMIT")

        return {
            "restored": restored,
            "restore_token": new_token,
            "token_expires_at": new_expires,
        }

    # ---------- 批量一次性令牌恢复 ----------

    async def restore_batch(self, items: list[RestoreBatchItem]) -> dict:
        """单个 IMMEDIATE 事务内完成整批恢复：先全部校验，再统一作废 + 轮换。

        任一项校验失败即整体回滚；已解密的恢复值仅存在于内存，随异常丢弃，
        不会产生任何部分副作用（旧令牌保持未用、不签发任何新令牌）。
        """
        now = utcnow()
        wanted_list = [self._dedup(item.placeholders) for item in items]
        token_hashes = [hash_token(item.token) for item in items]
        # 一次性令牌在同一批次中不得重复，否则同一张令牌会被消费两次
        if len(set(token_hashes)) != len(token_hashes):
            raise ServiceError("批次内存在重复的恢复令牌", 400)

        async with self.db.cursor() as cur:
            await cur.execute("BEGIN IMMEDIATE")
            try:
                # 阶段一（只读）：逐项校验令牌未用未过期、文档有效、占位符归属
                plans = [
                    await self._validate_restore_item(cur, th, wanted, now)
                    for th, wanted in zip(token_hashes, wanted_list)
                ]
                # 阶段二（写入）：全部通过后统一作废旧令牌并轮换新令牌
                results = []
                for plan in plans:
                    await cur.execute(
                        "UPDATE restore_tokens SET used = 1 WHERE token_hash = ?",
                        (plan["token_hash"],),
                    )
                    new_token = random_token()
                    new_expires = min(
                        now + timedelta(seconds=self.token_ttl), plan["doc_expires"]
                    )
                    await cur.execute(
                        "INSERT INTO restore_tokens"
                        " (token_hash, document_id, expires_at, used)"
                        " VALUES (?, ?, ?, 0)",
                        (hash_token(new_token), plan["doc_id"], to_iso(new_expires)),
                    )
                    results.append(
                        {
                            "restored": plan["restored"],
                            "restore_token": new_token,
                            "token_expires_at": new_expires,
                        }
                    )
                await cur.execute("COMMIT")
            except BaseException:
                # 任一项失败：整体回滚，不泄露其他项恢复值
                await cur.execute("ROLLBACK")
                raise

        return {"results": results}

    async def _validate_restore_item(
        self,
        cur: aiosqlite.Cursor,
        token_hash: str,
        wanted: list[str],
        now: datetime,
    ) -> dict:
        """批量恢复的单项只读校验（在已开启的事务内执行，不做任何写入）。

        校验顺序与单条恢复一致：令牌存在 / 未用 / 未过期 -> 文档仍有效 ->
        占位符均属于该文档。通过后把恢复内容解密进内存（不落盘），作为
        阶段二的轮换计划；任一检查失败抛错，由调用方整体回滚。
        """
        await cur.execute(
            "SELECT document_id, expires_at, used FROM restore_tokens"
            " WHERE token_hash = ?",
            (token_hash,),
        )
        token_row = await cur.fetchone()
        if token_row is None:
            raise UnauthorizedError("恢复令牌无效（可能已被使用）")
        if token_row["used"]:
            raise UnauthorizedError("恢复令牌已使用")
        if from_iso(token_row["expires_at"]) <= now:
            raise UnauthorizedError("恢复令牌已过期，请重新提交文档")

        doc_id = token_row["document_id"]
        await cur.execute("SELECT expires_at FROM documents WHERE id = ?", (doc_id,))
        doc_row = await cur.fetchone()
        if doc_row is None or from_iso(doc_row["expires_at"]) <= now:
            raise ExpiredError("文档映射已过期，无法恢复")
        doc_expires = from_iso(doc_row["expires_at"])

        await cur.execute(
            "SELECT placeholder, category, start_offset, end_offset, priority,"
            " cipher_value, source, rule_id FROM fragments"
            " WHERE document_id = ? AND kept = 1 ORDER BY start_offset",
            (doc_id,),
        )
        frag_rows = await cur.fetchall()
        by_placeholder: dict[str, list[aiosqlite.Row]] = {}
        for r in frag_rows:
            by_placeholder.setdefault(r["placeholder"], []).append(r)
        unknown = [p for p in wanted if p not in by_placeholder]
        if unknown:
            raise ServiceError(f"占位符不属于该文档：{unknown}", 400)

        restored: list[RestoredItem] = []
        for p in wanted:
            rows = by_placeholder[p]
            restored.append(
                RestoredItem(
                    placeholder=p,
                    category=rows[0]["category"],
                    value=self.crypto.decrypt(rows[0]["cipher_value"]),
                    occurrences=[
                        RestoredOccurrence(
                            start=r["start_offset"],
                            end=r["end_offset"],
                            priority=r["priority"],
                            source=r["source"],
                            rule_id=r["rule_id"],
                        )
                        for r in rows
                    ],
                )
            )
        return {
            "token_hash": token_hash,
            "doc_id": doc_id,
            "doc_expires": doc_expires,
            "restored": restored,
        }

    # ---------- 过期清理 ----------

    async def purge_expired(self) -> None:
        now_iso = to_iso(utcnow())
        await self.db.execute("DELETE FROM documents WHERE expires_at <= ?", (now_iso,))
        await self.db.execute("DELETE FROM restore_tokens WHERE expires_at <= ?", (now_iso,))
        await self.db.commit()

    # ---------- helpers ----------

    async def _delete_document(self, doc_id: str) -> None:
        await self.db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))

    @staticmethod
    def _dedup(placeholders: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for p in placeholders:
            if not PLACEHOLDER_PATTERN.fullmatch(p):
                raise ServiceError(f"非法占位符格式：{p!r}", 422)
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered

    @staticmethod
    def _fragment_out(sp) -> FragmentOut:
        return FragmentOut(
            fragment_id=sp.fragment_id,
            decision_rank=sp.decision_rank,
            blocked_by_fragment_id=sp.blocked_by_fragment_id,
            placeholder=sp.placeholder,
            category=sp.category,
            start=sp.start,
            end=sp.end,
            priority=sp.priority,
            kept=sp.kept,
            drop_reason=sp.drop_reason,
            source=sp.source,
            rule_id=sp.rule_id,
        )

    @staticmethod
    def _row_out(row: aiosqlite.Row) -> FragmentOut:
        return FragmentOut(
            fragment_id=row["fragment_id"],
            decision_rank=row["decision_rank"],
            blocked_by_fragment_id=row["blocked_by_fragment_id"],
            placeholder=row["placeholder"],
            category=row["category"],
            start=row["start_offset"],
            end=row["end_offset"],
            priority=row["priority"],
            kept=bool(row["kept"]),
            drop_reason=row["drop_reason"],
            source=row["source"],
            rule_id=row["rule_id"],
        )
