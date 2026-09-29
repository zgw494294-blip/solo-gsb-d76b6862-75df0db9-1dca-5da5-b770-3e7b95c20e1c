"""实物交接审计:按时间顺序重放交接事件,维护每件实物的持有人。

实物由 GTIN + AI 21 序列号唯一标识。事件按 occurred_at 转 UTC 升序处理,
同一时刻依输入顺序;只有成功事件才参与流转,失败事件按原下标记录原因:

- 扫描非法或缺少序列号:不参与流转;
- 实物首次事件 from_location 须为 null;
- 后续事件 from_location 须等于上次成功事件的 to_location;
- 批号 / 有效期须与首次成功扫描一致(含字段缺失),否则记录冲突且不改变持有人。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date as dt_date
from datetime import timezone

from .gs1 import ScanParseError, parse_scan
from .models import (
    CustodyAuditRequest,
    CustodyAuditResponse,
    CustodyEventError,
    CustodyItem,
)


@dataclass
class _ItemState:
    """单件实物的流转状态;批号 / 有效期以首次成功扫描为基准。"""

    batch: str | None
    expiry: dt_date | None
    holder: str
    events: list[int] = field(default_factory=list)


def _fmt_value(value: object) -> str:
    return "(缺失)" if value is None else f"'{value}'"


def audit_custody(request: CustodyAuditRequest) -> CustodyAuditResponse:
    """重放交接事件,返回每件实物的成功事件与最终持有人,以及失败事件的原因。"""
    order = sorted(
        range(len(request.events)),
        key=lambda i: (request.events[i].occurred_at.astimezone(timezone.utc), i),
    )
    states: dict[tuple[str, str], _ItemState] = {}
    errors: list[CustodyEventError] = []

    for index in order:
        event = request.events[index]
        try:
            parsed = parse_scan(event.scan)
        except ScanParseError as exc:
            errors.append(CustodyEventError(index=index, reason=f"扫描非法: {exc.reason}"))
            continue
        if parsed.serial is None:
            errors.append(
                CustodyEventError(index=index, reason="扫描串缺少 AI 21 序列号,无法识别实物")
            )
            continue

        key = (parsed.gtin, parsed.serial)
        state = states.get(key)
        if state is None:
            # 实物的首次成功事件:建立基准,from_location 须为 null
            if event.from_location is not None:
                errors.append(
                    CustodyEventError(
                        index=index,
                        reason=(
                            "实物首次事件的 from_location 须为 null,"
                            f"实际为 '{event.from_location}'"
                        ),
                    )
                )
                continue
            states[key] = _ItemState(
                batch=parsed.batch,
                expiry=parsed.expiry,
                holder=event.to_location,
                events=[index],
            )
            continue

        if event.from_location != state.holder:
            actual = "null" if event.from_location is None else f"'{event.from_location}'"
            errors.append(
                CustodyEventError(
                    index=index,
                    reason=(
                        f"from_location 须等于上次成功事件的 to_location '{state.holder}',"
                        f"实际为 {actual}"
                    ),
                )
            )
            continue
        if parsed.batch != state.batch:
            errors.append(
                CustodyEventError(
                    index=index,
                    reason=(
                        f"批号与首次成功扫描冲突: 首次为 {_fmt_value(state.batch)},"
                        f"本次为 {_fmt_value(parsed.batch)}"
                    ),
                )
            )
            continue
        if parsed.expiry != state.expiry:
            errors.append(
                CustodyEventError(
                    index=index,
                    reason=(
                        f"有效期与首次成功扫描冲突: 首次为 {_fmt_value(state.expiry)},"
                        f"本次为 {_fmt_value(parsed.expiry)}"
                    ),
                )
            )
            continue
        state.holder = event.to_location
        state.events.append(index)

    items = [
        CustodyItem(gtin=gtin, serial=serial, events=state.events, holder=state.holder)
        for (gtin, serial), state in states.items()
    ]
    items.sort(key=lambda item: (item.gtin, item.serial))
    errors.sort(key=lambda error: error.index)
    return CustodyAuditResponse(items=items, errors=errors)
