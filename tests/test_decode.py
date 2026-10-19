"""Decoder tests: build real signed transactions, check form detection,
witness extraction, signature verification, and block round-trips.
All local; no network."""

import hashlib
import json

import pytest

from bitcoin.core import (
    CBlock, CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint,
    CTxInWitness, CScriptWitness, CTxWitness, lx, x as to_x,
)
from bitcoin.core.script import (
    CScript, SignatureHash, SIGVERSION_WITNESS_V0, SIGVERSION_BASE,
    OP_0, OP_1, OP_2, OP_3, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DUP,
    OP_HASH160, OP_EQUAL, OP_EQUALVERIFY,
)
from bitcoin.core.script import CScriptOp
OP_CHECKSIGADD = CScriptOp(0xBA)
OP_GREATERTHANOREQUAL = CScriptOp(0xA1)
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress

from coincurve import PrivateKey

from msfp import decode
from msfp import scripts as S

# Test keys (never mainnet keys; deterministic test vectors).
PRIV1 = bytes.fromhex("11" * 32)
PRIV2 = bytes.fromhex("22" * 32)
PRIV3 = bytes.fromhex("33" * 32)
P1 = CBitcoinSecret.from_secret_bytes(PRIV1)
P2 = CBitcoinSecret.from_secret_bytes(PRIV2)
P3 = CBitcoinSecret.from_secret_bytes(PRIV3)
K1 = bytes(P1.pub)
K2 = bytes(P2.pub)
K3 = bytes(P3.pub)


def _sign_ecdsa(priv, sighash):
    return priv.sign(sighash, hasher=None)


def _make_p2wsh_2of3_spend(witness_script):
    """Funding tx + spending tx pair over a P2WSH 2-of-3 output."""
    spk = CScript([OP_0, hashlib.sha256(witness_script).digest()])
    fund = CMutableTransaction()
    fund.vout = [CMutableTxOut(10000, spk)]
    fund_txid = fund.GetHash()

    spend = CMutableTransaction()
    spend.vin = [CMutableTxIn(COutPoint(fund_txid, 0))]
    spend.vout = [CMutableTxOut(9000, CScript())]

    msg = SignatureHash(CScript(witness_script), spend, 0, 1, amount=10000,
                        sigversion=SIGVERSION_WITNESS_V0)
    sig1 = _sign_ecdsa(PrivateKey(PRIV1), msg) + b"\x01"
    sig2 = _sign_ecdsa(PrivateKey(PRIV2), msg) + b"\x01"
    sw = CScriptWitness(stack=[b"", sig1, sig2, bytes(witness_script)])
    spend.wit = CTxWitness(vtxinwit=[CTxInWitness(scriptWitness=sw)])
    return fund, spend


def test_p2wsh_multisig_full_pipeline():
    witness_script = bytes(CScript([OP_2, K1, K2, K3, OP_3,
                                    OP_CHECKMULTISIG]))
    fund, spend = _make_p2wsh_2of3_spend(witness_script)

    wit = [bytes(i) for i in spend.wit.vtxinwit[0].scriptWitness.stack]
    form = decode.classify_input(None, wit)
    assert form == "p2wsh"

    sigs = decode.extract_signatures(None, wit)
    assert len(sigs) == 2
    assert sigs[0][2] is False  # ECDSA, not Schnorr

    # Signature verification with ordered CHECKMULTISIG semantics.
    from msfp import verify
    summary = verify.verify_input_ecdsa(spend, 0, witness_script, 10000)
    assert summary["signatures_present"] == 2
    assert summary["signatures_verified"] == 2
    assert summary["keys_in_script"] == 3


def test_signature_verification_rejects_wrong_key_sigs():
    witness_script = bytes(CScript([OP_2, K1, K2, K3, OP_3,
                                    OP_CHECKMULTISIG]))
    _fund, spend = _make_p2wsh_2of3_spend(witness_script)
    # Corrupt one signature; ordered matching must leave it unverified.
    stack = [bytes(i) for i in spend.wit.vtxinwit[0].scriptWitness.stack]
    bad = bytearray(stack[1])
    bad[10] ^= 0xFF
    sw = CScriptWitness(stack=[stack[0], bytes(bad), stack[2], stack[3]])
    spend.wit = CTxWitness(vtxinwit=[CTxInWitness(scriptWitness=sw)])
    from msfp import verify
    summary = verify.verify_input_ecdsa(spend, 0, witness_script, 10000)
    assert summary["signatures_present"] == 2
    assert summary["signatures_verified"] == 1


def test_commitment_check_p2wsh_and_p2sh():
    script = b"\x51" + b"\x93" * 4
    from msfp import verify
    spk_wsh = b"\x00\x20" + hashlib.sha256(script).digest()
    assert verify.check_commitment(script, spk_wsh) is True
    spk_p2sh = b"\xa9\x14" + verify.hash160(script) + b"\x87"
    assert verify.check_commitment(script, spk_p2sh) is True
    tampered = bytearray(spk_wsh)
    tampered[10] ^= 1
    assert verify.check_commitment(script, bytes(tampered)) is False
    spk_tr = b"\x51\x20" + b"\x11" * 32
    assert verify.check_commitment(script, spk_tr) == "not_verifiable"
    assert verify.check_commitment(script, b"\x76\xa9\x14") == "not_applicable"


def test_commitment_check_nested_p2sh_p2wsh():
    """A P2SH prevout commits to the scriptSig's redeem push. For a
    nested P2SH-P2WSH spend that push is a segwit program, so the
    revealed witnessScript binds only through BOTH levels:
    sha256(witnessScript) -> program payload, hash160(program) -> P2SH
    hash. Comparing hash160(witnessScript) against the P2SH hash
    directly would reject every genuine nested spend."""
    from msfp import verify

    witness_script = bytes(CScript([OP_2, K1, K2, K3, OP_3,
                                    OP_CHECKMULTISIG]))
    program = b"\x00\x20" + hashlib.sha256(witness_script).digest()
    spk_p2sh = b"\xa9\x14" + verify.hash160(program) + b"\x87"
    script_sig = CScript([program]).hex()

    # Correct witnessScript, nested path: True.
    assert verify.check_commitment(witness_script, spk_p2sh,
                                   script_sig_hex=script_sig) is True
    # Without the scriptSig the direct (plain-P2SH) comparison runs and
    # must NOT pass: hash160(witnessScript) is not the P2SH hash.
    assert verify.check_commitment(witness_script, spk_p2sh) is False
    # Wrong witnessScript at the inner level: False even with the
    # scriptSig present.
    other = bytes(CScript([OP_2, K1, K3, K2, OP_3, OP_CHECKMULTISIG]))
    assert verify.check_commitment(other, spk_p2sh,
                                   script_sig_hex=script_sig) is False
    # Tampered P2SH hash: False.
    tampered = bytearray(spk_p2sh)
    tampered[5] ^= 1
    assert verify.check_commitment(witness_script, bytes(tampered),
                                   script_sig_hex=script_sig) is False
    # A plain P2SH spend (redeem push is the revealed script itself)
    # still checks directly, with or without the scriptSig.
    redeem = bytes(CScript([OP_1, K1, OP_1, OP_CHECKMULTISIG]))
    spk_plain = b"\xa9\x14" + verify.hash160(redeem) + b"\x87"
    ss = CScript([b"", b"\x30" * 70 + b"\x01", redeem]).hex()
    assert verify.check_commitment(redeem, spk_plain) is True
    assert verify.check_commitment(redeem, spk_plain,
                                   script_sig_hex=ss) is True


def test_nested_p2sh_p2wsh_spend_end_to_end():
    """Full synthetic nested spend: commitment, form classification, and
    ordered signature verification all agree on the same construction."""
    from msfp import decode
    from msfp import verify
    from coincurve import PrivateKey

    witness_script = bytes(CScript([OP_2, K1, K2, K3, OP_3,
                                    OP_CHECKMULTISIG]))
    program = b"\x00\x20" + hashlib.sha256(witness_script).digest()
    spk = CScript([OP_HASH160, verify.hash160(program), OP_EQUAL])

    fund = CMutableTransaction()
    fund.vout = [CMutableTxOut(10000, spk)]

    spend = CMutableTransaction()
    spend.vin = [CMutableTxIn(COutPoint(fund.GetHash(), 0),
                              scriptSig=CScript([program]))]
    spend.vout = [CMutableTxOut(9000, CScript())]

    msg = SignatureHash(CScript(witness_script), spend, 0, 1, amount=10000,
                        sigversion=SIGVERSION_WITNESS_V0)
    sig1 = _sign_ecdsa(PrivateKey(PRIV1), msg) + b"\x01"
    sig2 = _sign_ecdsa(PrivateKey(PRIV2), msg) + b"\x01"
    sw = CScriptWitness(stack=[b"", sig1, sig2, witness_script])
    spend.wit = CTxWitness(vtxinwit=[CTxInWitness(scriptWitness=sw)])

    script_sig_hex = bytes(spend.vin[0].scriptSig).hex()
    wit = [bytes(i) for i in sw.stack]
    assert decode.classify_input(script_sig_hex, wit) == "p2sh_p2wsh"
    assert verify.check_commitment(witness_script, bytes(spk),
                                   script_sig_hex=script_sig_hex) is True
    summary = verify.verify_input_ecdsa(spend, 0, witness_script, 10000)
    assert summary["signatures_present"] == 2
    assert summary["signatures_verified"] == 2


def _block_from_txs(txids_prev, txs, prev_hash=b"\x00" * 32, ntime=1700000000):
    # CBlock is immutable; build through the constructor. A zero merkle
    # root makes it compute the root from vtx itself.
    return CBlock(nVersion=0x20000000, hashPrevBlock=prev_hash,
                  hashMerkleRoot=b"\x00" * 32, nTime=ntime,
                  nBits=0x1702ac81, nNonce=1, vtx=txs)


def test_block_roundtrip_and_extraction():
    witness_script = bytes(CScript([OP_2, K1, K2, K3, OP_3,
                                    OP_CHECKMULTISIG]))
    fund, spend = _make_p2wsh_2of3_spend(witness_script)
    coinbase = CMutableTransaction()
    coinbase.vin = [CMutableTxIn(COutPoint())]
    coinbase.vout = [CMutableTxOut(5000000000, CScript())]

    block = _block_from_txs(None, [coinbase, spend])
    raw_hex = block.serialize().hex()

    decoded = decode.decode_block(raw_hex, 900000)
    records = decode.extract_input_records(decoded, 900000)
    # Coinbase input skipped; funding tx's input has null-ish prevout? No:
    # funding tx is not in this block. The spending tx's input points to
    # the funding tx (not in block) -> recorded.
    forms = [r["input_form"] for r in records]
    assert "p2wsh" in forms
    p2wsh = [r for r in records if r["input_form"] == "p2wsh"][0]
    source, raw_script = decode.revealed_script_for_input(p2wsh)
    assert source == "p2wsh_witness"
    assert raw_script == witness_script


def test_input_forms_recognized():
    # Legacy P2SH: scriptSig = OP_0 sig redeem.
    redeem = bytes(CScript([OP_1, K1, OP_1, OP_CHECKMULTISIG]))
    script_sig = CScript([b"", b"\x30" * 70 + b"\x01", redeem])
    form = decode.classify_input(script_sig.hex(), [])
    assert form == "p2sh_redeem"

    # P2PKH: scriptSig = sig pubkey. The trailing pubkey push is NOT a
    # redeem script even when its bytes happen to contain 0xAC
    # (OP_CHECKSIG) somewhere; raw pubkey bytes are never a script.
    sig = b"\x30\x44\x02\x20" + b"\x01" * 32 + b"\x02\x20" + b"\x02" * 32 + \
        b"\x01"
    pub_with_ac = bytes([0x02]) + b"\xac" * 32
    script_sig = CScript([sig, pub_with_ac])
    assert decode.classify_input(script_sig.hex(), []) == "legacy"
    # A pubkey whose last byte is OP_CHECKSIG is still a pubkey.
    pub_end_ac = bytes([0x02]) + b"\x11" * 31 + b"\xac"
    script_sig = CScript([sig, pub_end_ac])
    assert decode.classify_input(script_sig.hex(), []) == "legacy"

    # Nested P2SH-P2WSH: scriptSig = 0020{32}, witness with script.
    wscript = bytes(CScript([K1, OP_CHECKSIG]))
    program = b"\x00\x20" + hashlib.sha256(wscript).digest()
    script_sig = CScript([program])
    wit = [b"\x30" * 70 + b"\x01", wscript]
    form = decode.classify_input(script_sig.hex(), wit)
    assert form == "p2sh_p2wsh"

    # Taproot key-path: single 64-byte Schnorr sig.
    form = decode.classify_input(None, [b"\xee" * 64])
    assert form == "taproot_keypath"
    # Key-path with sighash byte.
    form = decode.classify_input(None, [b"\xee" * 64 + b"\x01"])
    assert form == "taproot_keypath"

    # Taproot key-path with annex.
    form = decode.classify_input(None, [b"\xee" * 64, b"\x50\x01"])
    assert form == "taproot_keypath"

    # Taproot script-path: control block last.
    control = b"\xc1" + b"\x42" * 32
    form = decode.classify_input(None, [b"\xee" * 64,
                                        bytes(CScript([K1, OP_CHECKSIG])),
                                        control])
    assert form == "taproot_scriptpath"

    # P2WPKH (DER-shaped signature + compressed key).
    fake_der = (b"\x30\x44\x02\x20" + b"\x01" * 32 +
                b"\x02\x20" + b"\x02" * 32 + b"\x01")
    form = decode.classify_input(None, [fake_der, K1])
    assert form == "p2wpkh"

    # Unknown / non-multisig legacy.
    form = decode.classify_input(CScript([b"\x01", b"\x02"]).hex(), [])
    assert form == "legacy"
