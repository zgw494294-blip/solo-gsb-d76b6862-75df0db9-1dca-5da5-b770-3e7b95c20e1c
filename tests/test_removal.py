"""POST /v1/custody/removal-plan 的端到端测试。"""

import random
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.gs1 import ScanParseError, parse_scan
from app.main import app

client = TestClient(app)

FNC1 = "\x1d"  # ASCII 29


def make_gtin(body13: str) -> str:
    """由 13 位本体计算模 10 校验位,生成合法 14 位 GTIN。"""
    assert len(body13) == 13 and body13.isdigit()
    total = sum(int(c) * (3 if i % 2 == 0 else 1) for i, c in enumerate(reversed(body13)))
    return body13 + str((10 - total % 10) % 10)


GTIN = make_gtin("0950600112345")
GTIN2 = make_gtin("0950600112346")


def scan(gtin=GTIN, batch="LOT1", serial="SN1", expiry="251231"):
    """按 01/17/10/21 顺序拼接扫描串(变长字段后视需要补 FNC1)。"""
    s = "01" + gtin
    if expiry is not None:
        s += "17" + expiry
    if batch is not None:
        s += "10" + batch
        if serial is not None:
            s += FNC1
    if serial is not None:
        s += "21" + serial
    return s


def event(scan_str, occurred_at, to_location, from_location=None):
    return {
        "scan": scan_str,
        "occurred_at": occurred_at,
        "from_location": from_location,
        "to_location": to_location,
    }


def post(events, locked_indices=None, expect=200):
    payload = {"events": events}
    if locked_indices is not None:
        payload["locked_indices"] = locked_indices
    resp = client.post("/v1/custody/removal-plan", json=payload)
    assert resp.status_code == expect, resp.text
    return resp.json() if expect == 200 else resp


# ---------- 正常路径 ----------

def test_valid_chain_fully_kept():
    events = [
        event(scan(), "2026-09-01T03:00:00Z", "WH-C", from_location="WH-B"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T02:00:00Z", "WH-B", from_location="WH-A"),
    ]
    body = post(events)
    assert body["kept_indices"] == [1, 2, 0]  # 处理顺序(时间升序)
    assert body["removed_indices"] == []
    assert body["items"] == [
        {"gtin": GTIN, "serial": "SN1", "events": [1, 2, 0], "holder": "WH-C"}
    ]


def test_broken_link_removed_minimally():
    events = [
        event(scan(), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-X"),  # 链断裂
        event(scan(), "2026-09-01T02:00:00Z", "WH-C", from_location="WH-A"),
    ]
    body = post(events)
    assert body["kept_indices"] == [0, 2]
    assert body["removed_indices"] == [1]
    assert body["items"][0]["holder"] == "WH-C"


def test_restart_event_dropped():
    # 第二条 from_location=null 的"重新开始"事件无法接在链上
    events = [
        event(scan(), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
        event(scan(), "2026-09-01T02:00:00Z", "WH-C"),
    ]
    body = post(events)
    assert body["kept_indices"] == [0, 1]
    assert body["removed_indices"] == [2]
    assert body["items"][0]["holder"] == "WH-B"


def test_batch_and_expiry_must_match_first_kept():
    events = [
        event(scan(batch="LOT1"), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(batch="LOT2"), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
        event(scan(batch="LOT1"), "2026-09-01T02:00:00Z", "WH-C", from_location="WH-A"),
        event(scan(batch="LOT1", expiry=None), "2026-09-01T03:00:00Z", "WH-D", from_location="WH-C"),
    ]
    body = post(events)
    assert body["kept_indices"] == [0, 2]
    assert body["removed_indices"] == [1, 3]


def test_first_kept_must_have_null_from_location():
    # 唯一事件的 from_location 非 null:只能全部剔除,实物不列出
    body = post([event(scan(), "2026-09-01T00:00:00Z", "WH-A", from_location="WH-X")])
    assert body["kept_indices"] == []
    assert body["removed_indices"] == [0]
    assert body["items"] == []


def test_invalid_scan_and_missing_serial_always_removed():
    events = [
        event("01" + GTIN + "99AB", "2026-09-01T00:00:00Z", "WH-A"),  # 未知 AI
        event(scan(serial=None), "2026-09-01T01:00:00Z", "WH-B"),  # 缺序列号
        event(scan(), "2026-09-01T02:00:00Z", "WH-C"),
    ]
    body = post(events)
    assert body["kept_indices"] == [2]
    assert body["removed_indices"] == [0, 1]
    assert body["items"] == [
        {"gtin": GTIN, "serial": "SN1", "events": [2], "holder": "WH-C"}
    ]


def test_items_sorted_by_gtin_then_serial():
    events = [
        event(scan(gtin=GTIN2, serial="SN2"), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(gtin=GTIN, serial="SN2"), "2026-09-01T00:00:00Z", "WH-B"),
        event(scan(gtin=GTIN, serial="SN1"), "2026-09-01T00:00:00Z", "WH-C"),
    ]
    body = post(events)
    assert [(i["gtin"], i["serial"]) for i in body["items"]] == [
        (GTIN, "SN1"),
        (GTIN, "SN2"),
        (GTIN2, "SN2"),
    ]
    assert [i["holder"] for i in body["items"]] == ["WH-C", "WH-B", "WH-A"]


# ---------- 并列时字典序最小 ----------

def test_tie_break_prefers_smaller_original_index():
    # 同一实物两条"重新开始"事件,只能留一条;保留下标序列 [0] < [1]
    events = [
        event(scan(), "2026-09-01T02:00:00Z", "WH-B"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-A"),
    ]
    body = post(events)
    assert body["kept_indices"] == [0]
    assert body["removed_indices"] == [1]
    assert body["items"][0]["holder"] == "WH-B"


def test_tie_break_is_global_not_per_item():
    # 处理顺序:idx1(t0) → idx0(t1) → idx2(t2);实物 SN-A 只能留一条。
    # 方案 {1,0} 的保留序列 [1,0] 与 {2,0} 的 [0,2] 并列,后者字典序更小。
    events = [
        event(scan(serial="SN-B"), "2026-09-01T01:00:00Z", "WH-Z"),
        event(scan(serial="SN-A"), "2026-09-01T00:00:00Z", "WH-X"),
        event(scan(serial="SN-A"), "2026-09-01T02:00:00Z", "WH-Y"),
    ]
    body = post(events)
    assert body["kept_indices"] == [0, 2]
    assert body["removed_indices"] == [1]
    holders = {item["serial"]: item["holder"] for item in body["items"]}
    assert holders == {"SN-A": "WH-Y", "SN-B": "WH-Z"}


# ---------- 锁定事件 ----------

def test_locked_restart_event_forces_drop_of_chain():
    events = [
        event(scan(), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
        event(scan(), "2026-09-01T02:00:00Z", "WH-C"),
    ]
    body = post(events, locked_indices=[2])
    assert body["kept_indices"] == [2]
    assert body["removed_indices"] == [0, 1]
    assert body["items"][0]["holder"] == "WH-C"


def test_locked_followup_forces_keeping_predecessor():
    events = [
        event(scan(), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
        event(scan(), "2026-09-01T02:00:00Z", "WH-C"),
    ]
    body = post(events, locked_indices=[1])
    assert body["kept_indices"] == [0, 1]
    assert body["removed_indices"] == [2]


def test_locked_invalid_scan_422():
    events = [
        event("01" + GTIN + "99AB", "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B"),
    ]
    post(events, locked_indices=[0], expect=422)


def test_locked_missing_serial_422():
    events = [
        event(scan(serial=None), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B"),
    ]
    post(events, locked_indices=[0], expect=422)


def test_locked_events_cannot_be_kept_together_422():
    # 两条锁定事件批号冲突,无法同时保留
    events = [
        event(scan(batch="LOT1"), "2026-09-01T00:00:00Z", "WH-A"),
        event(scan(batch="LOT2"), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
    ]
    post(events, locked_indices=[0, 1], expect=422)


def test_locked_first_event_non_null_from_422():
    events = [event(scan(), "2026-09-01T00:00:00Z", "WH-A", from_location="WH-X")]
    post(events, locked_indices=[0], expect=422)


def test_locked_broken_chain_422():
    # 锁定事件的前任被剔除后无法满足 from_location 约束
    events = [
        event(scan(), "2026-09-01T00:00:00Z", "WH-A", from_location="WH-X"),
        event(scan(), "2026-09-01T01:00:00Z", "WH-B", from_location="WH-A"),
    ]
    post(events, locked_indices=[1], expect=422)


# ---------- 请求体验证(422) ----------

def test_validation_event_count():
    post([], expect=422)
    post([event(scan(), "2026-09-01T00:00:00Z", "WH-A")] * 301, expect=422)
    post([event(scan(), "2026-09-01T00:00:00Z", "WH-A")] * 300)


def test_validation_locked_indices_unique_and_in_range():
    events = [event(scan(), "2026-09-01T00:00:00Z", "WH-A")]
    post(events, locked_indices=[0, 0], expect=422)  # 重复
    post(events, locked_indices=[1], expect=422)  # 越界
    post(events, locked_indices=[-1], expect=422)  # 越界
    post(events, locked_indices=[True], expect=422)  # 布尔拒绝
    post(events, locked_indices=[0])  # 合法


def test_validation_event_fields():
    post([event(scan(), "2026-09-01T00:00:00", "WH-A")], expect=422)  # 缺时区
    post([event(scan(), "2026-09-01T00:00:00Z", "")], expect=422)  # to_location 空
    post([dict(event(scan(), "2026-09-01T00:00:00Z", "A"), extra=1)], expect=422)
    resp = client.post(
        "/v1/custody/removal-plan",
        json={"events": [event(scan(), "2026-09-01T00:00:00Z", "A")], "extra": 1},
    )
    assert resp.status_code == 422


# ---------- 随机对拍:与暴力枚举一致 ----------

def _brute_force(events, locked):
    """暴力枚举保留子序列,返回 (kept_indices, removed_indices);"422" 表示整单 422。"""
    n = len(events)
    order = sorted(
        range(n),
        key=lambda i: (
            datetime.fromisoformat(events[i]["occurred_at"].replace("Z", "+00:00"))
            .astimezone(timezone.utc),
            i,
        ),
    )
    parsed = []
    for e in events:
        try:
            p = parse_scan(e["scan"])
            parsed.append(p if p.serial is not None else None)
        except ScanParseError:
            parsed.append(None)
    if any(parsed[i] is None for i in locked):  # 锁定事件必须剔除
        return "422"
    valid = [i for i in range(n) if parsed[i] is not None]
    best = None
    for mask in range(1 << len(valid)):
        kept_set = {valid[b] for b in range(len(valid)) if mask >> b & 1}
        if not all(idx in kept_set for idx in locked):
            continue
        kept = [i for i in order if i in kept_set]
        last_to = {}
        baseline = {}
        feasible = True
        for i in kept:
            p = parsed[i]
            key = (p.gtin, p.serial)
            if key not in last_to:
                if events[i]["from_location"] is not None:
                    feasible = False
                    break
                baseline[key] = (p.batch, p.expiry)
            else:
                if events[i]["from_location"] != last_to[key]:
                    feasible = False
                    break
                if (p.batch, p.expiry) != baseline[key]:
                    feasible = False
                    break
            last_to[key] = events[i]["to_location"]
        if not feasible:
            continue
        if best is None or len(kept) > len(best) or (len(kept) == len(best) and kept < best):
            best = kept
    if best is None:
        return "422"
    return best, sorted(set(range(n)) - set(best))


def test_random_against_brute_force():
    rng = random.Random(20260929)
    locations = ["WH-A", "WH-B", "WH-C"]
    serials = ["SN1", "SN2"]
    batches = [None, "LOT1", "LOT2"]
    expiries = [None, "251231", "260101"]
    n422 = 0
    for _ in range(400):
        n = rng.randint(1, 9)
        events = []
        for _ in range(n):
            kind = rng.random()
            if kind < 0.1:
                scan_str = "01" + rng.choice([GTIN, GTIN2]) + "99AB"  # 未知 AI
            else:
                scan_str = scan(
                    gtin=rng.choice([GTIN, GTIN2]),
                    batch=rng.choice(batches),
                    serial=None if kind < 0.2 else rng.choice(serials),
                    expiry=rng.choice(expiries),
                )
            events.append(
                event(
                    scan_str,
                    f"2026-09-01T{rng.randint(0, 5):02d}:00:00Z",
                    rng.choice(locations),
                    from_location=rng.choice([None] + locations),
                )
            )
        locked = sorted(rng.sample(range(n), rng.randint(0, n)))
        expected = _brute_force(events, locked)
        if expected == "422":
            post(events, locked_indices=locked, expect=422)
            n422 += 1
            continue
        body = post(events, locked_indices=locked)
        assert body["kept_indices"] == expected[0], events
        assert body["removed_indices"] == expected[1], events
        # 保留实物与最终持有人和暴力结果一致
        last_to = {}
        for i in expected[0]:
            p = parse_scan(events[i]["scan"])
            last_to[(p.gtin, p.serial)] = events[i]["to_location"]
        got_items = {(i["gtin"], i["serial"]): i["holder"] for i in body["items"]}
        assert got_items == last_to, events
        assert [(i["gtin"], i["serial"]) for i in body["items"]] == sorted(last_to)
    assert n422 > 0  # 确保 422 路径被覆盖
