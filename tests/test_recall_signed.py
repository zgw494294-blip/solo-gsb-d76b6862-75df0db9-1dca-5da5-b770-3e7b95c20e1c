"""POST /v1/recall/check-signed 的端到端测试。"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import signed
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

FNC1 = "\x1d"  # ASCII 29

KID = "recall-key-test-001"
OTHER_KID = "recall-key-test-002"
GTIN = "09506001123454"  # make_gtin("0950600112345")
GTIN2 = "09506001123461"  # 同前缀 0950600
GTIN_OTHER = "08591234567893"  # make_gtin("0859123456789"),不同前缀
NBF = 1_789_999_000
NOW = 1_790_000_000
EXP = 1_790_086_400

SCAN = "]d2" + "01" + GTIN + "17" + "251231" + "10" + "LOT1" + FNC1 + "21SN9"
RULE = {
    "id": "recall-2026-001",
    "gtin": GTIN,
    "batch": "LOT1",
    "date_from": "2025-01-01",
    "date_to": "2026-12-31",
}


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def other_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def trust_file(tmp_path, monkeypatch, private_key, other_private_key):
    """把模块默认信任文件路径指向临时文件,内含测试 kid。"""
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": KID,
                        "public_key": _public_b64(private_key),
                        "gtin_prefixes": ["0950600"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(signed, "DEFAULT_TRUST_FILE", str(path))
    return path


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url(raw)


def make_jws(
    private_key: Ed25519PrivateKey,
    payload: object,
    *,
    kid: str = KID,
    header: dict | None = None,
    sign: bool = True,
    bad_signature: bool = False,
    raw_header: str | None = None,
    raw_payload: str | None = None,
) -> str:
    header_obj = {"alg": "EdDSA", "kid": kid} if header is None else header
    header_seg = (
        raw_header
        if raw_header is not None
        else _b64url(json.dumps(header_obj, separators=(",", ":")).encode())
    )
    payload_seg = (
        raw_payload
        if raw_payload is not None
        else _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    if not sign:
        signature_seg = ""
    else:
        signature = private_key.sign(f"{header_seg}.{payload_seg}".encode("ascii"))
        if bad_signature:
            signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        signature_seg = _b64url(signature)
    return f"{header_seg}.{payload_seg}.{signature_seg}"


def valid_payload(**overrides) -> dict:
    payload = {"nbf": NBF, "exp": EXP, "rules": [RULE]}
    payload.update(overrides)
    return payload


def post(jws: str, *, scans=None, now: int = NOW):
    return client.post(
        "/v1/recall/check-signed",
        json={"scans": scans if scans is not None else [SCAN], "jws": jws, "now": now},
    )


# ---------- 正常路径 ----------


def test_valid_signed_check(private_key):
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["kid"] == KID
    (result,) = body["results"]
    assert result["ok"] is True
    assert result["fields"] == {
        "gtin": GTIN,
        "batch": "LOT1",
        "serial": "SN9",
        "date": "2025-12-31",
    }
    assert result["matches"] == ["recall-2026-001"]
    assert result["error"] is None


def test_per_scan_parse_error_still_inline(private_key):
    bad_scan = "01" + GTIN + "99"
    resp = post(make_jws(private_key, valid_payload()), scans=[SCAN, bad_scan, SCAN])
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [r["ok"] for r in results] == [True, False, True]
    assert results[1]["error"]["reason"].startswith("未知 AI")
    assert results[0]["matches"] == ["recall-2026-001"]


def test_nbf_inclusive_lower_bound(private_key):
    payload = valid_payload(nbf=NOW)
    assert post(make_jws(private_key, payload), now=NOW).status_code == 200


def test_exp_exclusive_upper_bound(private_key):
    payload = valid_payload(exp=NOW)
    resp = post(make_jws(private_key, payload), now=NOW)
    assert resp.status_code == 403
    assert "越期" in resp.json()["detail"]


def test_time_window_before_nbf_is_403(private_key):
    resp = post(make_jws(private_key, valid_payload(nbf=NOW + 1)), now=NOW)
    assert resp.status_code == 403


def test_time_window_after_exp_is_403(private_key):
    resp = post(make_jws(private_key, valid_payload(exp=NOW)), now=NOW + 1)
    assert resp.status_code == 403


# ---------- 授权前缀 ----------


def test_unauthorized_gtin_prefix_is_403(private_key):
    rule = {**RULE, "id": "foreign", "gtin": GTIN_OTHER}
    resp = post(make_jws(private_key, valid_payload(rules=[rule])))
    assert resp.status_code == 403
    assert "授权" in resp.json()["detail"]


def test_every_rule_must_be_authorized(private_key):
    rule2 = {**RULE, "id": "recall-2026-002", "gtin": GTIN_OTHER}
    resp = post(make_jws(private_key, valid_payload(rules=[RULE, rule2])))
    assert resp.status_code == 403


def test_shorter_prefix_matches(private_key, trust_file):
    # 14 位前缀即精确相等:换成精确前缀后,其他 GTIN 不再被授权
    trust_file.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": KID,
                        "public_key": _public_b64(private_key),
                        "gtin_prefixes": [GTIN],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert post(make_jws(private_key, valid_payload())).status_code == 200
    rule2 = {**RULE, "id": "r2", "gtin": GTIN2}
    assert post(make_jws(private_key, valid_payload(rules=[rule2]))).status_code == 403


# ---------- 签名 / 密钥 ----------


def test_bad_signature_is_403(private_key):
    resp = post(make_jws(private_key, valid_payload(), bad_signature=True))
    assert resp.status_code == 403
    assert "签名验证失败" in resp.json()["detail"]


def test_wrong_key_is_403(private_key, other_private_key):
    # 用信任文件中不存在的密钥签名,但头部 kid 仍指向受信 kid
    resp = post(make_jws(other_private_key, valid_payload()))
    assert resp.status_code == 403


def test_unknown_kid_is_403(private_key):
    resp = post(make_jws(private_key, valid_payload(), kid="nobody"))
    assert resp.status_code == 403
    assert "未知密钥" in resp.json()["detail"]


def test_missing_trust_file_is_500(private_key, monkeypatch):
    monkeypatch.setattr(signed, "DEFAULT_TRUST_FILE", "/nonexistent/trust.json")
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 500


# ---------- JWS 结构 / 编码:422 ----------


def test_wrong_segment_count_is_422(private_key):
    jws = make_jws(private_key, valid_payload())
    for broken in (jws + ".x", "a.b", "abc", ""):
        resp = post(broken)
        assert resp.status_code in (422,), broken
        assert resp.status_code == 422, broken


def test_empty_segment_is_422(private_key):
    jws = make_jws(private_key, valid_payload(), sign=False)
    assert post(jws).status_code == 422  # 空签名段
    # 空头 / 空载荷段
    assert post(".x.y").status_code == 422


def test_base64_padding_rejected(private_key):
    header_seg = _b64url(json.dumps({"alg": "EdDSA", "kid": KID}).encode()) + "="
    payload_seg = _b64url(json.dumps(valid_payload()).encode())
    sig = _b64url(private_key.sign(f"{header_seg}.{payload_seg}".encode()))
    assert post(f"{header_seg}.{payload_seg}.{sig}").status_code == 422


def test_base64_illegal_character_rejected(private_key):
    jws = make_jws(private_key, valid_payload())
    header_seg, payload_seg, sig = jws.split(".")
    assert post(f"{header_seg}!.{payload_seg}.{sig}").status_code == 422
    # 标准 base64 的 '+' / '/' 也不允许
    assert post(f"{header_seg}+.{payload_seg}.{sig}").status_code == 422


# ---------- 头部:422 ----------


def test_header_alg_wrong(private_key):
    jws = make_jws(private_key, valid_payload(), header={"alg": "ES256", "kid": KID})
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(), header={"alg": "EdDSA", "kid": ""})
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(), header={"alg": "EdDSA", "kid": 1})
    assert post(jws).status_code == 422


def test_header_extra_or_missing_keys(private_key):
    jws = make_jws(
        private_key, valid_payload(), header={"alg": "EdDSA", "kid": KID, "typ": "JWT"}
    )
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(), header={"alg": "EdDSA"})
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(), header={"kid": KID})
    assert post(jws).status_code == 422


def test_header_not_object(private_key):
    raw = _b64url(b"[1,2]")
    payload_seg = _b64url(json.dumps(valid_payload()).encode())
    jws = f"{raw}.{payload_seg}.x"
    assert post(jws).status_code == 422


def test_header_duplicate_json_keys(private_key):
    # {"alg":"EdDSA","kid":"...","kid":"..."} 手工构造重复键
    dup = (
        '{"alg":"EdDSA","kid":"' + KID + '","kid":"' + KID + '"}'
    ).encode()
    payload_seg = _b64url(json.dumps(valid_payload()).encode())
    header_seg = _b64url(dup)
    sig = _b64url(private_key.sign(f"{header_seg}.{payload_seg}".encode()))
    assert post(f"{header_seg}.{payload_seg}.{sig}").status_code == 422


# ---------- 载荷结构:422 ----------


def test_payload_not_object(private_key):
    jws = make_jws(private_key, [1, 2, 3])
    assert post(jws).status_code == 422


def test_payload_extra_or_missing_keys(private_key):
    jws = make_jws(private_key, {"nbf": NBF, "exp": EXP, "rules": [RULE], "iss": "x"})
    assert post(jws).status_code == 422
    jws = make_jws(private_key, {"exp": EXP, "rules": [RULE]})
    assert post(jws).status_code == 422
    jws = make_jws(private_key, {"nbf": NBF, "exp": EXP})
    assert post(jws).status_code == 422


def test_payload_nbf_exp_must_be_integer(private_key):
    jws = make_jws(private_key, valid_payload(nbf="1789999000"))
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(nbf=1.5))
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(exp=True))
    assert post(jws).status_code == 422


def test_payload_rules_must_be_nonempty_list(private_key):
    jws = make_jws(private_key, valid_payload(rules=[]))
    assert post(jws).status_code == 422
    jws = make_jws(private_key, valid_payload(rules=RULE))
    assert post(jws).status_code == 422


def test_payload_duplicate_top_level_keys(private_key):
    # {"nbf":..,"exp":..,"rules":[..],"rules":[..]}
    dup = (
        '{"nbf":%d,"exp":%d,"rules":[%s],"rules":[%s]}'
        % (NBF, EXP, json.dumps(RULE, separators=(",", ":")), json.dumps(RULE, separators=(",", ":")))
    ).encode()
    header_seg = _b64url(json.dumps({"alg": "EdDSA", "kid": KID}).encode())
    payload_seg = _b64url(dup)
    sig = _b64url(private_key.sign(f"{header_seg}.{payload_seg}".encode()))
    assert post(f"{header_seg}.{payload_seg}.{sig}").status_code == 422


def test_payload_duplicate_key_inside_rule(private_key):
    dup_rule = (
        '{"id":"r","id":"r","gtin":"%s"}' % GTIN
    ).encode()
    dup_payload = (
        b'{"nbf":%d,"exp":%d,"rules":[%s]}' % (NBF, EXP, dup_rule)
    )
    header_seg = _b64url(json.dumps({"alg": "EdDSA", "kid": KID}).encode())
    payload_seg = _b64url(dup_payload)
    sig = _b64url(private_key.sign(f"{header_seg}.{payload_seg}".encode()))
    assert post(f"{header_seg}.{payload_seg}.{sig}").status_code == 422


# ---------- 载荷规则格式:422(即使越权也先按格式) ----------


def test_invalid_rule_gtin_check_digit_is_422(private_key):
    bad_gtin = GTIN[:-1] + str((int(GTIN[-1]) + 1) % 10)
    jws = make_jws(private_key, valid_payload(rules=[{**RULE, "gtin": bad_gtin}]))
    assert post(jws).status_code == 422


def test_duplicate_rule_ids_is_422(private_key):
    jws = make_jws(
        private_key,
        valid_payload(rules=[RULE, {**RULE, "gtin": GTIN2}]),
    )
    assert post(jws).status_code == 422


def test_rule_date_range_reversed_is_422(private_key):
    jws = make_jws(
        private_key,
        valid_payload(
            rules=[{**RULE, "date_from": "2026-01-01", "date_to": "2025-01-01"}]
        ),
    )
    assert post(jws).status_code == 422


def test_rule_extra_field_is_422(private_key):
    jws = make_jws(
        private_key, valid_payload(rules=[{**RULE, "unexpected": 1}])
    )
    assert post(jws).status_code == 422


def test_too_many_rules_is_422(private_key):
    rules = [{**RULE, "id": f"r{i}"} for i in range(101)]
    jws = make_jws(private_key, valid_payload(rules=rules))
    assert post(jws).status_code == 422


# ---------- 请求体:422 ----------


def test_request_body_validation(private_key):
    jws = make_jws(private_key, valid_payload())

    def raw_post(body):
        return client.post("/v1/recall/check-signed", json=body)

    assert raw_post({"scans": [], "jws": jws, "now": NOW}).status_code == 422
    assert raw_post({"scans": [SCAN] * 101, "jws": jws, "now": NOW}).status_code == 422
    assert raw_post({"scans": [SCAN], "jws": "", "now": NOW}).status_code == 422
    assert raw_post({"scans": [SCAN], "jws": jws}).status_code == 422  # 缺 now
    assert raw_post({"scans": [SCAN], "jws": jws, "now": True}).status_code == 422
    assert raw_post({"scans": [SCAN], "jws": jws, "now": NOW, "x": 1}).status_code == 422


# ---------- 签名输入必须是原始前两段 ----------


def test_signature_over_decoded_bytes_fails(private_key):
    header_seg = _b64url(json.dumps({"alg": "EdDSA", "kid": KID}).encode())
    payload_seg = _b64url(json.dumps(valid_payload()).encode())
    # 错误做法:对解码后的字节签名
    import base64

    decoded = (
        base64.urlsafe_b64decode(header_seg + "==")
        + b"."
        + base64.urlsafe_b64decode(payload_seg + "==")
    )
    sig = _b64url(private_key.sign(decoded))
    resp = post(f"{header_seg}.{payload_seg}.{sig}")
    assert resp.status_code == 403
