"""GS1 扫码核验 API:召回规则匹配 + 实物交接审计 + 交接日志最少剔除方案。"""

from __future__ import annotations

from fastapi import FastAPI

from .checker import check_scans
from .custody import audit_custody
from .isolation import build_isolation_plan
from .models import (
    CheckRequest,
    CheckResponse,
    CustodyAuditRequest,
    CustodyAuditResponse,
    CustodyRemovalPlanRequest,
    CustodyRemovalPlanResponse,
    IsolationPlanRequest,
    IsolationPlanResponse,
    PackingAuditRequest,
    PackingAuditResponse,
    ReceivingReconcileRequest,
    ReceivingReconcileResponse,
    RuleRelationsRequest,
    RuleRelationsResponse,
    SignedCheckRequest,
    SignedCheckResponse,
)
from .packing import audit_packing
from .receiving import reconcile
from .relations import analyze_rule_relations
from .removal import build_removal_plan
from .signed import check_signed

app = FastAPI(
    title="GS1 扫码核验 API",
    version="1.7.0",
    summary="解析 GS1 扫描串(AI 01/10/17/21):召回规则匹配、EdDSA 签名核验、规则关系分析、实物交接重放、交接日志最少剔除、装拆包装审计、召回隔离计划与到货核对",
)


@app.get("/healthz", tags=["meta"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/recall/check", response_model=CheckResponse, tags=["recall"])
def recall_check(request: CheckRequest) -> CheckResponse:
    """逐条解析扫描串并匹配召回规则;单条解析失败不影响其余条目。"""
    return CheckResponse(results=check_scans(request.scans, request.rules))


@app.post(
    "/v1/recall/check-signed", response_model=SignedCheckResponse, tags=["recall"]
)
def recall_check_signed(request: SignedCheckRequest) -> SignedCheckResponse:
    """先验 Ed25519 JWS、时间窗与授权 GTIN 前缀,全部通过再执行原扫码核验。"""
    return check_signed(request)


@app.post("/v1/custody/audit", response_model=CustodyAuditResponse, tags=["custody"])
def custody_audit(request: CustodyAuditRequest) -> CustodyAuditResponse:
    """按时间(UTC 升序)重放交接事件,审计每件实物(GTIN+序列号)的持有人流转。"""
    return audit_custody(request)


@app.post(
    "/v1/custody/removal-plan",
    response_model=CustodyRemovalPlanResponse,
    tags=["custody"],
)
def custody_removal_plan(
    request: CustodyRemovalPlanRequest,
) -> CustodyRemovalPlanResponse:
    """生成交接日志最少剔除方案:剔除数最少,并列时保留下标序列字典序最小。"""
    return build_removal_plan(request)


@app.post("/v1/packing/audit", response_model=PackingAuditResponse, tags=["packing"])
def packing_audit(request: PackingAuditRequest) -> PackingAuditResponse:
    """按输入顺序重放装入/取出操作,审计实物(GTIN+序列号)间的直接包装关系。"""
    return audit_packing(request)


@app.post(
    "/v1/recall/isolation-plan", response_model=IsolationPlanResponse, tags=["recall"]
)
def recall_isolation_plan(request: IsolationPlanRequest) -> IsolationPlanResponse:
    """库存扫描命中召回规则后,沿最终包装父链归并到最高层已封签祖先,输出隔离单元。"""
    return build_isolation_plan(request)


@app.post(
    "/v1/recall/rule-relations", response_model=RuleRelationsResponse, tags=["recall"]
)
def recall_rule_relations(request: RuleRelationsRequest) -> RuleRelationsResponse:
    """上线前比较召回规则的命中集合:列出不可能命中的规则与有交集的规则对。"""
    return analyze_rule_relations(request)


@app.post(
    "/v1/receiving/reconcile",
    response_model=ReceivingReconcileResponse,
    tags=["receiving"],
)
def receiving_reconcile(
    request: ReceivingReconcileRequest,
) -> ReceivingReconcileResponse:
    """核对到货实扫与期望明细:全局最优核销,返回已收分配、缺额与多余扫描。"""
    return reconcile(request)
