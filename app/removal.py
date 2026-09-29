"""交接日志最少剔除方案:在交接约束下选择保留子序列,使剔除事件总数最少。

实物由 GTIN + AI 21 序列号唯一标识;事件按 occurred_at 转 UTC 升序、同刻按
输入顺序处理。保留子序列的约束与交接审计一致,但判定基准是"上一条保留事件":

- 扫描非法或缺少 AI 21 序列号的事件必须剔除;若被锁定则整单 422;
- 每件实物首条保留事件的 from_location 须为 null;
- 后续保留事件的 from_location 须等于上一条保留事件的 to_location;
- 批号 / 有效期须与首条保留事件一致(含字段缺失);
- 锁定事件必须保留;锁定事件无法同时保留时整单 422。

目标:剔除总数最少(即保留最多);并列时按处理顺序排列的保留原下标序列
字典序最小。

实现:对每件实物做位图 DP,求"保留全部锁定事件前提下,从任意后缀与状态出发
可达的保留数集合";随后全局贪心逐条构造字典序最小的保留序列——每步在所有
"保留后仍可行"的候选事件中选原下标最小者。并列比较的是全局处理顺序合并后
的下标序列,不能按实物各自贪心(保留他实物的小下标事件可能更优)。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date as dt_date
from datetime import timezone

from fastapi import HTTPException

from .gs1 import ScanParseError, parse_scan
from .models import (
    CustodyRemovalItem,
    CustodyRemovalPlanRequest,
    CustodyRemovalPlanResponse,
)

ItemKey = tuple[str, str]


def _unprocessable(reason: str) -> HTTPException:
    return HTTPException(status_code=422, detail=reason)


@dataclass
class _Event:
    """一条可参与流转的有效事件(扫描合法且含 AI 21 序列号)。"""

    index: int  # 原下标
    pos: int  # 处理顺序位置(UTC 升序,同刻按输入顺序)
    from_location: str | None
    to_location: str
    batch: str | None
    expiry: dt_date | None
    locked: bool


def _keepable(events: list[_Event], i: int, j: int) -> bool:
    """第 i 条事件能否接在第 j 条保留事件之后保留(j=-1 表示作为首条)。"""
    event = events[i]
    if j == -1:
        return event.from_location is None
    prev = events[j]
    return (
        event.from_location == prev.to_location
        and event.batch == prev.batch
        and event.expiry == prev.expiry
    )


def _achievable_counts(events: list[_Event]) -> list[list[int]]:
    """位图 DP:poss[i][j+1] 的第 r 位为 1,表示"已保留到第 j 条(j=-1 表示尚无
    保留),从第 i 条起往后,在保留该后缀内全部锁定事件的前提下,恰好再保留 r 条"
    是可达的。"""
    m = len(events)
    poss = [[0] * (m + 1) for _ in range(m + 1)]
    for jj in range(m + 1):
        poss[m][jj] = 1  # 后缀为空:恰好再保留 0 条
    for i in range(m - 1, -1, -1):
        event = events[i]
        keep_bits = poss[i + 1][i + 1] << 1  # 保留第 i 条:状态变为"最后保留第 i 条"
        for jj in range(i + 1):
            bits = keep_bits if _keepable(events, i, jj - 1) else 0
            if not event.locked:
                bits |= poss[i + 1][jj]  # 剔除第 i 条(锁定事件不可剔除)
            poss[i][jj] = bits
    return poss


def build_removal_plan(request: CustodyRemovalPlanRequest) -> CustodyRemovalPlanResponse:
    """生成最少剔除方案:保留下标(处理顺序)、剔除下标(升序)与保留实物。"""
    events = request.events
    n = len(events)
    locked = set(request.locked_indices)

    # 处理顺序:occurred_at 转 UTC 升序,同刻按输入顺序
    order = sorted(
        range(n), key=lambda i: (events[i].occurred_at.astimezone(timezone.utc), i)
    )

    # 复用现有 GS1 解析;非法或缺序列号的事件必须剔除,被锁定时整单 422
    items: dict[ItemKey, list[_Event]] = {}
    flat: list[tuple[ItemKey, _Event]] = []  # 全部有效事件,按处理顺序
    for index in order:
        event = events[index]
        try:
            parsed = parse_scan(event.scan)
        except ScanParseError as exc:
            if index in locked:
                raise _unprocessable(
                    f"锁定事件 {index} 扫描非法({exc.reason}),必须剔除,无法保留"
                ) from exc
            continue
        if parsed.serial is None:
            if index in locked:
                raise _unprocessable(
                    f"锁定事件 {index} 缺少 AI 21 序列号,必须剔除,无法保留"
                )
            continue
        key = (parsed.gtin, parsed.serial)
        entry = _Event(
            index=index,
            pos=len(flat),  # 处理顺序位置(仅计可参与流转的有效事件)
            from_location=event.from_location,
            to_location=event.to_location,
            batch=parsed.batch,
            expiry=parsed.expiry,
            locked=index in locked,
        )
        items.setdefault(key, []).append(entry)
        flat.append((key, entry))

    # 每件实物的位图 DP 与保留配额(保留全部锁定事件前提下的最大保留数)
    keys = sorted(items)
    poss = {key: _achievable_counts(items[key]) for key in keys}
    need: dict[ItemKey, int] = {}
    for key in keys:
        if poss[key][0][0] == 0:
            raise _unprocessable(
                f"实物 (GTIN {key[0]}, 序列号 '{key[1]}') 的锁定事件无法同时保留"
            )
        need[key] = poss[key][0][0].bit_length() - 1

    # 全局贪心:每步在"保留后仍可完成全部配额"的候选中选原下标最小者
    ptr = {key: 0 for key in keys}  # 各实物下一条未决定事件(实物内下标)
    last = {key: -1 for key in keys}  # 各实物最后一条保留事件(实物内下标)
    locked_positions = sorted(entry.pos for _, entry in flat if entry.locked)
    next_locked = 0  # 第一个尚未保留的锁定事件在 locked_positions 中的下标
    kept_indices: list[int] = []
    kept_events: dict[ItemKey, list[_Event]] = {key: [] for key in keys}
    cursor = 0
    total = sum(need.values())
    for _ in range(total):
        # 候选为处理位置 cursor..limit 的事件;越过 limit 会跳过未保留的锁定事件
        limit = (
            locked_positions[next_locked]
            if next_locked < len(locked_positions)
            else len(flat) - 1
        )
        # 扫描候选;dptr 为"假设剔除 cursor..p-1 后"各实物的未决定指针,
        # ok / bad 维护各实物在当前假设下能否完成剩余配额
        dptr = dict(ptr)
        ok = {
            key: (poss[key][dptr[key]][last[key] + 1] >> need[key]) & 1
            for key in keys
        }
        bad = sum(1 for key in keys if not ok[key])
        chosen: tuple[int, ItemKey, int] | None = None  # (原下标, 实物, 实物内下标)
        for p in range(cursor, limit + 1):
            key, entry = flat[p]
            i = dptr[key]
            if (
                need[key] > 0
                and _keepable(items[key], i, last[key])
                and (poss[key][i + 1][i + 1] >> (need[key] - 1)) & 1
                and bad - (0 if ok[key] else 1) == 0
            ):
                if chosen is None or entry.index < chosen[0]:
                    chosen = (entry.index, key, i)
            # 对更靠后的候选而言,位置 p 的事件已被剔除:推进指针并维护可行性
            dptr[key] += 1
            now_ok = (poss[key][dptr[key]][last[key] + 1] >> need[key]) & 1
            if now_ok != ok[key]:
                ok[key] = now_ok
                bad += -1 if now_ok else 1
        assert chosen is not None, "存在可行解时贪心必然找到候选事件"
        index, key, i = chosen
        # 提交选择:剔除 cursor..p_star-1 之间的全部事件,保留位置 p_star 的事件
        p_star = items[key][i].pos
        for other in keys:
            while (
                ptr[other] < len(items[other])
                and items[other][ptr[other]].pos < p_star
            ):
                ptr[other] += 1
        ptr[key] = i + 1
        last[key] = i
        need[key] -= 1
        if items[key][i].locked:
            next_locked += 1
        cursor = p_star + 1
        kept_indices.append(index)
        kept_events[key].append(items[key][i])

    kept_set = set(kept_indices)
    item_models = [
        CustodyRemovalItem(
            gtin=key[0],
            serial=key[1],
            events=[entry.index for entry in kept_events[key]],
            holder=kept_events[key][-1].to_location,
        )
        for key in keys
        if kept_events[key]  # 未保留任何事件的实物不列出
    ]
    return CustodyRemovalPlanResponse(
        kept_indices=kept_indices,
        removed_indices=[i for i in range(n) if i not in kept_set],
        items=item_models,
    )
