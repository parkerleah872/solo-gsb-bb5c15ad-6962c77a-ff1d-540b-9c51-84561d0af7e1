"""文档脱敏、查询、恢复的业务逻辑。"""
from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import uuid
from datetime import datetime, timedelta

import aiosqlite

from app.crypto import CryptoBox, InvalidToken, random_token
from app.fingerprint import fingerprint_text
from app.policy_engine import ProcessRuleRunner, apply_rules, compile_rules
from app.redaction import (
    AUTO,
    PLACEHOLDER_PATTERN,
    InputSpan,
    redact,
    validate_category,
)
from app.schemas import (
    DEFAULT_DUPLICATE_LIMIT,
    MAX_DUPLICATE_LIMIT,
    FragmentOut,
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

logger = logging.getLogger(__name__)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
        created_iso = to_iso(now)
        fp = fingerprint_text(req.text)
        doc_expires = now + timedelta(seconds=ttl)
        token = random_token()
        # 令牌有效期不超过文档映射本身
        token_expires = min(now + timedelta(seconds=self.token_ttl), doc_expires)

        async with self.db.cursor() as cur:
            await cur.execute(
                "INSERT INTO documents"
                " (id, ciphertext, redacted, expires_at, policy_id,"
                " fingerprint, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    doc_id,
                    self.crypto.encrypt(req.text),
                    result.redacted_text,
                    to_iso(doc_expires),
                    req.policy_id,
                    fp,
                    created_iso,
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
        self, document_id: str, limit: int | None = None, cursor: str | None = None
    ) -> dict:
        """解密文档原文、按 NFC 规范化计算 SHA-256 指纹，返回其他未过期重复文档。

        指纹以本次解密原文实时计算为准（不信任库内可能尚未回填的值），并顺带
        把缺失的指纹落库（懒回填，幂等）。结果只含 ID / 指纹 / 创建时间 /
        匹配类型，绝不返回原文、脱敏文或占位符。分页采用 (created_at, id)
        键集游标，保证按创建时间稳定排序、翻页不重不漏。
        """
        if limit is None:
            limit = DEFAULT_DUPLICATE_LIMIT
        if not 1 <= limit <= MAX_DUPLICATE_LIMIT:
            raise ServiceError(
                f"limit 必须在 1..{MAX_DUPLICATE_LIMIT} 之间", 422
            )
        cur_created, cur_id = self._decode_cursor(cursor)

        async with await self.db.execute(
            "SELECT id, ciphertext, expires_at, fingerprint, created_at"
            " FROM documents WHERE id = ?",
            (document_id,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            raise NotFoundError("文档不存在或已过期删除")
        if from_iso(row["expires_at"]) <= utcnow():
            await self._delete_document(document_id)
            await self.db.commit()
            raise ExpiredError("文档映射已过期")

        fp = fingerprint_text(self.crypto.decrypt(row["ciphertext"]))
        # 懒回填：旧库迁移后指纹可能为 NULL
        if row["fingerprint"] is None:
            await self.db.execute(
                "UPDATE documents SET fingerprint = ? WHERE id = ?",
                (fp, document_id),
            )
            await self.db.commit()

        now_iso = to_iso(utcnow())
        # 多取一行判断是否还有下一页；(created_at, id) 与游标做行值比较
        sql = (
            "SELECT id, fingerprint, created_at FROM documents"
            " WHERE fingerprint = ? AND id != ? AND expires_at > ?"
            " AND (created_at > ? OR (created_at = ? AND id > ?))"
            " ORDER BY created_at ASC, id ASC LIMIT ?"
        )
        params = (fp, document_id, now_iso, cur_created, cur_created, cur_id, limit + 1)
        async with await self.db.execute(sql, params) as cur:
            rows = await cur.fetchall()

        has_next = len(rows) > limit
        page = rows[:limit]
        next_cursor = None
        if has_next:
            next_cursor = self._encode_cursor(page[-1]["created_at"], page[-1]["id"])

        return {
            "document_id": document_id,
            "fingerprint": fp,
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

    async def backfill_fingerprints(self) -> int:
        """启动时回填旧库：解密 fingerprint IS NULL 的文档，计算 NFC 指纹落库。

        幂等：只处理仍为 NULL 的行；逐行解密，单行失败（如密钥不匹配）只记录
        警告并跳过，不阻断启动——该行在被访问重复检测接口时会再次尝试懒回填。
        返回回填行数。
        """
        async with await self.db.execute(
            "SELECT id, ciphertext FROM documents WHERE fingerprint IS NULL"
        ) as cur:
            pending = await cur.fetchall()
        backfilled = 0
        for r in pending:
            try:
                plaintext = self.crypto.decrypt(r["ciphertext"])
            except (InvalidToken, ValueError):
                logger.warning(
                    "文档 %s 指纹回填失败：原文无法用当前密钥解密，已跳过",
                    r["id"],
                )
                continue
            await self.db.execute(
                "UPDATE documents SET fingerprint = ? WHERE id = ? AND fingerprint IS NULL",
                (fingerprint_text(plaintext), r["id"]),
            )
            backfilled += 1
        if backfilled:
            await self.db.commit()
            logger.info("已回填 %d 个旧文档的重复检测指纹", backfilled)
        return backfilled

    @staticmethod
    def _encode_cursor(created_at: str, document_id: str) -> str:
        raw = f"{created_at}|{document_id}".encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[str, str]:
        if cursor is None:
            # 首页：created_at 取空串（ISO 字符串字典序均大于它），id 取空串
            return "", ""
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            created_at, document_id = raw.split("|", 1)
            from_iso(created_at)  # 校验时间格式
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            raise ServiceError("非法分页游标", 400) from exc
        if len(document_id) != 32:
            raise ServiceError("非法分页游标", 400)
        return created_at, document_id

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
