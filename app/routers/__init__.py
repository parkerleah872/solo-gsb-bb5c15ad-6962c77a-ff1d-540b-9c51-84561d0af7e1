"""HTTP 路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.schemas import (
    DocumentResponse,
    DuplicatesResponse,
    PolicyCreateRequest,
    PolicyResponse,
    RestoreBatchRequest,
    RestoreBatchResponse,
    RestoreRequest,
    RestoreResponse,
    SubmitRequest,
    SubmitResponse,
    MAX_DUPLICATE_LIMIT,
)
from app.services.document_service import DocumentService
from app.services.policy_service import PolicyService

router = APIRouter()


def get_service(request: Request) -> DocumentService:
    return request.app.state.service


def get_policy_service(request: Request) -> PolicyService:
    return request.app.state.policy_service


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def create_policy(
    payload: PolicyCreateRequest,
    service: PolicyService = Depends(get_policy_service),
) -> dict:
    """创建自动脱敏策略（不可变）；每条规则含 rule_id、类别、正则、优先级。"""
    return await service.create(payload)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    service: PolicyService = Depends(get_policy_service),
) -> dict:
    """查询自动脱敏策略及其全部规则（按创建顺序）。"""
    return await service.get(policy_id)


@router.post("/documents", response_model=SubmitResponse, status_code=201)
async def submit(
    payload: SubmitRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """提交原文与敏感片段，返回脱敏文本、片段明细与一次性恢复令牌。

    可传 ``policy_id``：服务端按策略规则在 Unicode 原文上生成自动片段，与
    客户端 ``spans`` 合并后统一做重叠消解。
    """
    return await service.submit(payload)


@router.get("/documents/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: str,
    service: DocumentService = Depends(get_service),
) -> dict:
    """查询脱敏文本与片段明细（不含任何原文信息，无需令牌）。"""
    return await service.get(document_id)


@router.post("/documents/{document_id}/duplicates", response_model=DuplicatesResponse)
async def find_duplicates(
    document_id: str,
    limit: int = Query(50, ge=1, le=MAX_DUPLICATE_LIMIT, description="单页返回条数上限"),
    cursor: str | None = Query(None, description="上一页响应中的 next_cursor"),
    service: DocumentService = Depends(get_service),
) -> dict:
    """重复检测：服务端解密该文档原文并按 NFC 规范化计算 SHA-256 指纹，
    返回其他未过期的同指纹文档（exact_normalized）。

    响应只含匹配文档 ID、指纹、创建时间与匹配类型，不含原文或占位符；
    结果按 (创建时间, 文档 ID) 稳定升序分页。
    """
    return await service.find_duplicates(document_id, limit, cursor)


@router.post("/restore", response_model=RestoreResponse)
async def restore(
    payload: RestoreRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """凭一次性令牌还原指定占位符；令牌用后作废并轮换返回新令牌。"""
    return await service.restore(payload.token, payload.placeholders)


@router.post("/restore/batch", response_model=RestoreBatchResponse)
async def restore_batch(
    payload: RestoreBatchRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """批量一次性恢复（1～20 项）：单事务先校验全部令牌再统一作废轮换，
    任一项失败整体回滚，响应按请求顺序返回。"""
    return await service.restore_batch(payload.items)
