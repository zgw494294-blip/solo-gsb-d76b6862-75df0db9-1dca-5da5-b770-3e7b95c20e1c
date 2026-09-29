"""装拆包装审计:按输入顺序重放装入(pack)/取出(unpack)操作,维护包装关系。

实物由 GTIN + AI 21 序列号唯一标识。父件、子件两端复用现有 GS1 解析,
均须含 AI 21,否则该操作按原下标报错。

- 装入:子件须尚无父件,且不能是父件本身或父件的祖先(防止自装 / 成环);
  父件若此前未出现,记为无父件的新实物。
- 取出:父件、子件均须为已知实物,且父件必须是子件的当前直接父件。

失败操作不改变任何包装关系,后续操作继续处理。
"""

from __future__ import annotations

from .gs1 import ScanParseError, parse_scan
from .models import (
    PackingAuditRequest,
    PackingAuditResponse,
    PackingError,
    PackingItem,
    PackingItemRef,
    PackingOperation,
)

# 实物标识:GTIN + AI 21 序列号
ItemKey = tuple[str, str]


def _ref(key: ItemKey) -> PackingItemRef:
    return PackingItemRef(gtin=key[0], serial=key[1])


def _item_label(key: ItemKey) -> str:
    return f"实物 (GTIN {key[0]}, 序列号 '{key[1]}')"


def _parse_item(raw_scan: str, role: str, index: int) -> tuple[ItemKey | None, str | None]:
    """解析一端扫描串;失败时返回 (None, 含原下标与角色的原因)。"""
    try:
        parsed = parse_scan(raw_scan)
    except ScanParseError as exc:
        return None, f"操作 {index} 的{role}扫描非法: {exc.reason}"
    if parsed.serial is None:
        return None, f"操作 {index} 的{role}扫描串缺少 AI 21 序列号,无法识别实物"
    return (parsed.gtin, parsed.serial), None


def replay_packing(
    operations: list[PackingOperation],
) -> tuple[dict[ItemKey, ItemKey], set[ItemKey], list[PackingError]]:
    """按输入顺序重放装/拆操作,返回 (最终父子边, 成功操作涉及的实物, 失败原因)。

    失败操作不改变任何关系,按原下标记录原因;只有成功操作涉及的实物
    才计入 known。供装拆包装审计与召回隔离计划复用。
    """
    # parent_of[child] = parent,即每条直接父子边
    parent_of: dict[ItemKey, ItemKey] = {}
    known: set[ItemKey] = set()  # 出现在成功操作中的全部实物
    errors: list[PackingError] = []

    for index, op in enumerate(operations):
        parent_key, err = _parse_item(op.parent_scan, "父件", index)
        if err is not None:
            errors.append(PackingError(index=index, reason=err))
            continue
        child_key, err = _parse_item(op.child_scan, "子件", index)
        if err is not None:
            errors.append(PackingError(index=index, reason=err))
            continue
        assert parent_key is not None and child_key is not None

        if op.action == "pack":
            if child_key in parent_of:
                errors.append(
                    PackingError(
                        index=index,
                        reason=(
                            f"装入失败:子件{_item_label(child_key)}已有直接父件"
                            f"{_item_label(parent_of[child_key])},不能重复装入"
                        ),
                    )
                )
                continue
            if child_key == parent_key:
                errors.append(
                    PackingError(
                        index=index,
                        reason="装入失败:子件不能与父件为同一实物",
                    )
                )
                continue
            # 沿父链向上检查 child 是否为 parent 的祖先(含 parent 本身,已在上面排除)
            ancestor: ItemKey | None = parent_of.get(parent_key)
            cyclic = False
            seen: set[ItemKey] = set()
            while ancestor is not None:
                if ancestor == child_key:
                    cyclic = True
                    break
                if ancestor in seen:  # 防御性:正常维护下不会出现环
                    break
                seen.add(ancestor)
                ancestor = parent_of.get(ancestor)
            if cyclic:
                errors.append(
                    PackingError(
                        index=index,
                        reason=(
                            f"装入失败:子件{_item_label(child_key)}是父件{_item_label(parent_key)}"
                            "的祖先,装入将形成循环包装"
                        ),
                    )
                )
                continue
            parent_of[child_key] = parent_key
            known.add(child_key)
            known.add(parent_key)
        else:  # unpack
            if parent_key not in known:
                errors.append(
                    PackingError(
                        index=index,
                        reason=f"取出失败:指定的父件{_item_label(parent_key)}此前未出现在任何成功操作中",
                    )
                )
                continue
            if child_key not in known:
                errors.append(
                    PackingError(
                        index=index,
                        reason=f"取出失败:指定的子件{_item_label(child_key)}此前未出现在任何成功操作中",
                    )
                )
                continue
            if parent_of.get(child_key) != parent_key:
                current = parent_of.get(child_key)
                if current is None:
                    actual = "子件当前无直接父件"
                else:
                    actual = f"子件的当前直接父件为{_item_label(current)}"
                errors.append(
                    PackingError(
                        index=index,
                        reason=(
                            f"取出失败:{actual},并非指定的父件{_item_label(parent_key)}"
                        ),
                    )
                )
                continue
            del parent_of[child_key]
            # 取出不移除实物:两端仍属成功操作涉及的实物

    return parent_of, known, errors


def audit_packing(request: PackingAuditRequest) -> PackingAuditResponse:
    """按输入顺序重放装/拆操作,返回成功操作涉及实物的当前包装关系与失败原因。"""
    parent_of, known, errors = replay_packing(request.operations)

    # 反向收集每个父件的当前直接子件
    children_of: dict[ItemKey, list[ItemKey]] = {}
    for child, parent in parent_of.items():
        children_of.setdefault(parent, []).append(child)

    def root_of(key: ItemKey) -> ItemKey:
        """沿父链走到最外层容器。"""
        node = key
        guard: set[ItemKey] = set()
        while node in parent_of and node not in guard:
            guard.add(node)
            node = parent_of[node]
        return node

    items = [
        PackingItem(
            gtin=key[0],
            serial=key[1],
            parent=_ref(parent_of[key]) if key in parent_of else None,
            children=[_ref(c) for c in sorted(children_of.get(key, []))],
            root=_ref(root_of(key)),
        )
        for key in known
    ]
    items.sort(key=lambda item: (item.gtin, item.serial))
    errors.sort(key=lambda error: error.index)
    return PackingAuditResponse(items=items, errors=errors)
