"""Attribution engine tests (synthetic registry rows only, no network)."""

from msfp.attribute import (
    _timelock_matches,
    grade_script,
    match_liana_multi_a,
    match_structure,
    parse_timelocks,
    script_features,
    xpub_to_pubkey,
)


def _feats(**over):
    base = {
        "script_sha256": "a" * 64,
        "source": "p2wsh_witness",
        "forms": {"p2wsh"},
        "script_class": "multisig",
        "family_l4": "standard_multisig",
        "threshold": 2,
        "n_keys": 3,
        "keys_sorted": 0,
        "template_l3": "OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG",
        "timelocks": [],
        "csv_values": [],
        "cltv_values": [],
    }
    base.update(over)
    return base


def test_xpub_to_pubkey_bip32_vector():
    # BIP32 test vector 1, chain m: independent reference value.
    xpub = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY"
            "2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert xpub_to_pubkey(xpub) == \
        "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"


def test_xpub_to_pubkey_rejects_bad_checksum():
    xpub = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY"
            "2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    assert xpub_to_pubkey(xpub[:-3] + "aaa") is None
    assert xpub_to_pubkey("not-an-xpub") is None


def test_parse_timelocks():
    l2 = ("<PUBKEY> OP_CHECKSIGVERIFY <PUBKEY> OP_CHECKSIG OP_IFDUP OP_NOTIF "
          "<NUM:51840> OP_CHECKSEQUENCEVERIFY OP_ENDIF")
    assert parse_timelocks(l2) == [("OP_CHECKSEQUENCEVERIFY", 51840)]
    assert parse_timelocks(None) == []


def test_timelock_buckets_are_alternatives_not_conjunctions():
    # Green documents three CSV buckets; an account uses exactly one.
    struct = {"timelocks": [{"op": "CSV", "value": 25920},
                            {"op": "CSV", "value": 51840},
                            {"op": "CSV", "value": 65535}]}
    ok, hits = _timelock_matches(
        struct, _feats(timelocks=[("OP_CHECKSEQUENCEVERIFY", 51840)],
                       csv_values=[51840]))
    assert ok
    assert hits == ["CSV=51840 documented by provider"]
    ok, _ = _timelock_matches(
        struct, _feats(timelocks=[("OP_CHECKSEQUENCEVERIFY", 30000)],
                       csv_values=[30000]))
    assert not ok


def test_timelock_null_value_demands_op_presence_only():
    struct = {"timelocks": [{"op": "CSV", "value": None}]}
    ok, hits = _timelock_matches(
        struct, _feats(timelocks=[("OP_CHECKSEQUENCEVERIFY", 999)]))
    assert ok and hits == ["CSV present"]
    ok, _ = _timelock_matches(struct, _feats())
    assert not ok


def test_row_without_timelocks_demands_script_without_timelocks():
    ok, _ = _timelock_matches({"timelocks": []}, _feats())
    assert ok
    ok, _ = _timelock_matches(
        {"timelocks": []},
        _feats(timelocks=[("OP_CHECKSEQUENCEVERIFY", 100)]))
    assert not ok


def test_structure_match_exact_join():
    struct = {
        "form": "p2wsh", "script_class": "multisig", "threshold": 2,
        "n_keys": 3, "keys_sorted": False, "timelocks": [],
        "template_l3": "OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG",
    }
    ok, pins = match_structure(struct, _feats())
    assert ok and "template_l3 exact" in pins
    # A sorted script does not match a documented-unsorted row.
    ok, _ = match_structure(struct, _feats(keys_sorted=1))
    assert not ok
    # A form the script was never revealed under does not match.
    ok, _ = match_structure(struct, _feats(forms={"p2sh_redeem"}))
    assert not ok


def test_non_discriminating_row_is_refused():
    struct = {"form": "taproot_scriptpath", "script_class": "other",
              "threshold": None, "n_keys": None, "keys_sorted": None,
              "timelocks": [], "template_l3": None}
    ok, why = match_structure(
        struct, _feats(source="taproot_leaf", forms={"taproot_scriptpath"},
                       script_class="other", threshold=None, n_keys=2,
                       keys_sorted=None, template_l3="<P> OP_CHECKSIG"))
    assert not ok and why == ["non_discriminating"]


def test_liana_multi_a_primary_feature_check():
    struct = {"form": "taproot_scriptpath", "script_class": "other",
              "threshold": 2, "n_keys": None, "keys_sorted": False,
              "timelocks": [], "template_l3": None}
    feats = _feats(source="taproot_leaf", forms={"taproot_scriptpath"},
                   script_class="taproot_multisig", threshold=2, n_keys=2,
                   keys_sorted=0,
                   template_l3="<P> OP_CHECKSIG <P> 0xba OP_2 OP_NUMEQUAL")
    ok, pins = match_liana_multi_a(struct, feats)
    assert ok and "multi_a primary leaf 2-of-2 (k-of-k)" in pins


def test_grade_script_green_csv_is_c_and_shape_alone_is_d():
    green_csv = {
        "structure_id": "blockstream_green#3", "provider": {"id": "green"},
        "form": "p2sh_p2wsh", "script_class": "other", "threshold": None,
        "n_keys": 2, "keys_sorted": False,
        "timelocks": [{"op": "CSV", "value": 25920},
                      {"op": "CSV", "value": 51840},
                      {"op": "CSV", "value": 65535}],
        "template_l3": ("<P> OP_CHECKSIGVERIFY <P> OP_CHECKSIG OP_IFDUP "
                        "OP_NOTIF <T> OP_CHECKSEQUENCEVERIFY OP_ENDIF"),
    }
    bitgo = {
        "structure_id": "bitgo#0", "provider": {"id": "bitgo"},
        "form": "p2wsh", "script_class": "multisig", "threshold": 2,
        "n_keys": 3, "keys_sorted": False, "timelocks": [],
        "template_l3": "OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG",
    }
    index = {"structures": [green_csv, bitgo]}
    # Documented bucket value plus form: strong implementation match.
    feats = _feats(
        source="p2wsh_witness", forms={"p2sh_p2wsh"}, script_class="other",
        threshold=None, n_keys=2, keys_sorted=None,
        template_l3=("<P> OP_CHECKSIGVERIFY <P> OP_CHECKSIG OP_IFDUP "
                     "OP_NOTIF <T> OP_CHECKSEQUENCEVERIFY OP_ENDIF"),
        timelocks=[("OP_CHECKSEQUENCEVERIFY", 51840)], csv_values=[51840])
    hits = grade_script(feats, index)
    assert hits["green"]["grade"] == "C"
    assert "bitgo" not in hits
    # The same shape through a non-documented form matches nothing.
    feats["forms"] = {"p2wsh"}
    assert grade_script(feats, index) == {}
    # Bare 2-of-3 shape: weak match only.
    feats = _feats()
    hits = grade_script(feats, index)
    assert hits["bitgo"]["grade"] == "D"
