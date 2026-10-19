"""Classifier and template tests (synthetic scripts only, no network)."""

import hashlib

import pytest

from bitcoin.core.script import CScript, CScriptOp

from msfp import scripts as S
from msfp.scripts import (
    OP_0, OP_1, OP_2, OP_3, OP_CHECKMULTISIG, OP_CHECKSIG,
    OP_CHECKSIGADD, OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKSEQUENCEVERIFY,
    OP_CHECKLOCKTIMEVERIFY, OP_SHA256, OP_EQUALVERIFY, OP_DROP,
    OP_GREATERTHANOREQUAL, OP_CHECKSIGVERIFY,
)

K1 = bytes.fromhex("02" + "11" * 32)
K2 = bytes.fromhex("03" + "22" * 32)
K3 = bytes.fromhex("02" + "33" * 32)
X1 = "44" * 32  # x-only key bytes


def _hexs(b):
    return bytes.hex(b) if isinstance(b, (bytes, bytearray)) else b


def test_standard_2of3_multisig():
    raw = bytes(CScript([OP_2, K1, K2, K3, OP_3, OP_CHECKMULTISIG]))
    a = S.analyze_script(raw)
    assert a["script_class"] == "multisig"
    assert a["threshold"] == 2 and a["n_keys"] == 3
    assert a["keys_sorted"] is False  # K3 < K1 lexically? no: 22.. < 33.. etc.
    assert a["family_l4"] == "standard_multisig"
    assert len(a["pubkeys"]) == 3
    assert a["script_sha256"] == hashlib.sha256(raw).hexdigest()


def test_sorted_vs_unsorted_distinguished():
    sorted_keys = sorted([K1, K2, K3])
    raw_sorted = bytes(CScript([OP_2] + sorted_keys + [OP_3,
                                                       OP_CHECKMULTISIG]))
    raw_unsorted = bytes(CScript([OP_2, K3, K1, K2, OP_3, OP_CHECKMULTISIG]))
    a_s = S.analyze_script(raw_sorted)
    a_u = S.analyze_script(raw_unsorted)
    assert a_s["keys_sorted"] is True
    assert a_u["keys_sorted"] is False
    # Same L2 template, different L1.
    assert a_s["template_l2"] == a_u["template_l2"]
    assert a_s["script_sha256"] != a_u["script_sha256"]


def test_template_normalization_merges_unrelated_keys():
    other1 = bytes.fromhex("02" + "ee" * 32)
    other2 = bytes.fromhex("03" + "ff" * 32)
    raw_a = bytes(CScript([OP_2, K1, K2, K3, OP_3, OP_CHECKMULTISIG]))
    raw_b = bytes(CScript([OP_2, other1, other2, K3, OP_3,
                           OP_CHECKMULTISIG]))
    a = S.analyze_script(raw_a)
    b = S.analyze_script(raw_b)
    assert a["template_l2"] == b["template_l2"]
    assert a["template_l3"] == b["template_l3"]
    # Same template, different exact scripts: template equality never
    # implies shared keys (the overlap here is one key; the point is
    # that only the L1 hashes distinguish the actual scripts).
    assert a["script_sha256"] != b["script_sha256"]


def test_csv_recovery_multisig():
    csv_value = 0x2A  # 42 blocks
    raw = bytes(CScript([OP_2, K1, K2, K3, OP_3, OP_CHECKMULTISIG, OP_DROP,
                         csv_value, OP_CHECKSEQUENCEVERIFY, OP_DROP]))
    a = S.analyze_script(raw)
    assert a["script_class"] == "multisig"
    assert a["family_l4"] == "timelocked_recovery_multisig"
    # L2 keeps the timelock value; L3 normalizes it.
    assert "<NUM:42>" in a["template_l2"]
    assert "<T>" in a["template_l3"]
    assert "<NUM:42>" not in a["template_l3"]


def test_cltv_absolute_recovery():
    raw = bytes(CScript([800000, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                         OP_1, K1, OP_1, OP_CHECKMULTISIG]))
    a = S.analyze_script(raw)
    assert a["family_l4"] == "timelocked_recovery_multisig"
    assert "<NUM:800000>" in a["template_l2"]
    assert a["timelocks"][0]["value"] == 800000


def test_conditional_policy():
    raw = bytes(CScript([OP_IF, OP_2, K1, K2, OP_2, OP_CHECKMULTISIG,
                         OP_ELSE, K3, OP_CHECKSIG, OP_ENDIF]))
    a = S.analyze_script(raw)
    assert a["family_l4"] == "conditional_multisig"
    assert a["conditionals"]["if"] == 1
    # Keys appear in both branches; the single quorum inside the IF is
    # recorded but the whole script is a compound, not a plain multisig.
    assert a["script_class"] == "compound_multisig"


def test_hashlock():
    digest = b"\xab" * 20
    raw = bytes(CScript([OP_SHA256, digest, OP_EQUALVERIFY, K1, OP_CHECKSIG]))
    a = S.analyze_script(raw)
    assert a["hashlocks"][0]["digest_hex"] == digest.hex()
    assert a["family_l4"] == "hashlock_policy"


def test_tapscript_checksigadd_chain():
    x1 = bytes.fromhex(X1)
    x2 = bytes.fromhex("55" * 32)
    x3 = bytes.fromhex("66" * 32)
    raw = bytes(CScript([x1, OP_CHECKSIGADD, x2, OP_CHECKSIGADD,
                         x3, OP_CHECKSIGADD, OP_2,
                         OP_GREATERTHANOREQUAL]))
    a = S.analyze_script(raw, tapscript=True)
    assert a["script_class"] == "taproot_multisig"
    assert a["threshold"] == 2 and a["n_keys"] == 3
    assert a["family_l4"] == "taproot_scriptpath_multisig"
    # 32-byte x-only keys recognized only adjacent to CHECKSIGADD.
    assert all(len(k) == 32 for k in a["pubkeys"])
    assert a["keys_sorted"] is True


def test_32byte_push_not_adjacent_to_sigop_is_not_a_key():
    digest32 = b"\x99" * 32
    raw = bytes(CScript([OP_SHA256, digest32, OP_EQUALVERIFY,
                         bytes.fromhex(X1), OP_CHECKSIG]))
    a = S.analyze_script(raw, tapscript=True)
    assert len(a["pubkeys"]) == 1
    assert a["pubkeys"][0] == bytes.fromhex(X1)


def test_tapscript_conditional_recovery_family():
    x1 = bytes.fromhex(X1)
    x2 = bytes.fromhex("77" * 32)
    raw = bytes(CScript([x1, OP_CHECKSIGVERIFY, 144, OP_CHECKSEQUENCEVERIFY,
                         x2, OP_CHECKSIG]))
    a = S.analyze_script(raw, tapscript=True)
    assert a["family_l4"] == "taproot_conditional_recovery"


def test_unparseable_script_preserved():
    bad = b"\x4c"  # OP_PUSHDATA4 with no length bytes -> truncated push
    a = S.analyze_script(bad)
    assert a["script_class"] == "unparseable"
    assert a["script_hex"] == bad.hex()
    assert a["parse_error"] is not None


def test_signature_shape_detection():
    # Minimal DER: r and s one byte each, plus a sighash byte.
    der = bytes.fromhex("3006020101020101" + "01")
    assert S.is_der_signature(der) is True
    assert S.is_der_signature(b"\x02" + der[1:]) is False
    assert S.is_der_signature(b"\x30\x02\x02\x01\x00") is False  # too short
    schnorr = b"\xee" * 64
    s, ht = S.split_sighash(schnorr, schnorr=True)
    assert len(s) == 64 and ht == 0x00
    s, ht = S.split_sighash(schnorr + b"\x81", schnorr=True)
    assert len(s) == 64 and ht == 0x81


def test_l2_preserves_thresholds_and_branch_structure():
    raw = bytes(CScript([3, K1, K2, K3, bytes.fromhex("02" + "aa" * 32),
                         5, OP_CHECKMULTISIG]))
    a = S.analyze_script(raw)
    assert "OP_3" in a["template_l2"] and "OP_5" in a["template_l2"]
    assert a["template_l2"].count("<PUBKEY>") == 4


def test_inscription_envelope_is_not_recovery():
    # Common Taproot inscription construction: key spend followed by
    # OP_FALSE OP_IF "ord" payload OP_ENDIF. The branch is unexecuted data.
    x1 = bytes.fromhex(X1)
    raw = bytes(CScript([x1, OP_CHECKSIG, OP_0, OP_IF, b"ord",
                         b"text/plain", b"hello", OP_ENDIF]))
    a = S.analyze_script(raw, tapscript=True)
    assert a["family_l4"] == "taproot_inscription_envelope"
    assert a["threshold"] is None
    assert a["script_class"] == "other"
