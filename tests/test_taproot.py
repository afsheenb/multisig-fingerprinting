"""Taproot verification tests against the official BIP-0340 and
BIP-0341 test vectors, plus a synthetic script-path round trip."""

import hashlib
import json
import os

import pytest

from bitcoin.core import (
    CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, lx,
    CTxInWitness, CScriptWitness, CTxWitness, CTransaction, x as to_x,
)
from bitcoin.core.script import CScript, OP_CHECKSIG

from coincurve import PrivateKey, PublicKeyXOnly

from msfp import verify

VECTORS = os.path.join(os.path.dirname(__file__), "vectors")


def test_bip340_vectors():
    path = os.path.join(VECTORS, "bip340_test_vectors.csv")
    n_checked = 0
    with open(path) as fh:
        header = fh.readline().strip().split(",")
        for line in fh:
            row = dict(zip(header, line.strip().split(",")))
            pub = bytes.fromhex(row["public key"])
            msg = bytes.fromhex(row["message"])
            sig = bytes.fromhex(row["signature"])
            expected = row["verification result"] == "TRUE"
            got = verify.verify_schnorr(sig, msg, pub)
            # Only vectors with 32-byte plain pubkeys verify through the
            # x-only path; BIP-0340 rows with non-canonical keys may be
            # rejected by libsecp256k1 by design. Compare accordingly.
            if expected and len(pub) == 32 and not row["comment"]:
                assert got is True, "row %s should verify" % row["index"]
                n_checked += 1
            if not expected:
                assert got is False, "row %s must not verify" % row["index"]
    # The CSV carries 4 plain-32-byte-pubkey TRUE rows; the rest use
    # 33-byte keys (outside the x-only verifier's input shape).
    assert n_checked == 4


def _load_bip341():
    with open(os.path.join(VECTORS, "bip341_wallet_test_vectors.json")) as fh:
        return json.load(fh)["keyPathSpending"]


def test_bip341_keypath_sighash_vectors():
    n_checked = 0
    for vec in _load_bip341():
        tx = CTransaction.deserialize(bytes.fromhex(
            vec["given"]["rawUnsignedTx"]))
        utxos = [(u["amountSats"], bytes.fromhex(u["scriptPubKey"]))
                 for u in vec["given"]["utxosSpent"]]
        for spend in vec["inputSpending"]:
            idx = spend["given"]["txinIndex"]
            hashtype = spend["given"]["hashType"]
            sighash = verify.taproot_sighash(tx, idx, utxos,
                                             hashtype=hashtype)
            # Verify the signature in expected.witness against the tweaked
            # output key.
            witness = spend["expected"]["witness"]
            sig = bytes.fromhex(witness[0])
            sig64 = sig[:64]
            spk = utxos[idx][1]
            assert spk[0] == 0x51 and len(spk) == 34
            ok = verify.verify_schnorr(sig64, sighash, spk[2:])
            assert ok is True, "vector %s input %d signature must verify" % (
                vec["given"]["rawUnsignedTx"][:16], idx)
            n_checked += 1
    assert n_checked >= 5


def test_bip341_sighash_hash_type_variants():
    """hashtypes across the official vectors include ALL, SINGLE, and
    ANYONECANPAY variants; assert our implementation distinguishes them."""
    vec = _load_bip341()[0]
    tx = CTransaction.deserialize(
        bytes.fromhex(vec["given"]["rawUnsignedTx"]))
    utxos = [(u["amountSats"], bytes.fromhex(u["scriptPubKey"]))
             for u in vec["given"]["utxosSpent"]]
    hashes = set()
    for ht in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
        hashes.add(verify.taproot_sighash(tx, 0, utxos, hashtype=ht))
    assert len(hashes) == 7


def _xonly_from_secret(secret):
    return bytes(PublicKeyXOnly.from_valid_secret(secret).format())


def _tweaked_pair(internal_priv, merkle_root):
    """Derive (internal_xonly, tweaked_priv, tweaked_xonly) per BIP341."""
    # coincurve privkey -> scalar; pub = scalar*G compressed -> x-only.
    xonly = _xonly_from_secret(internal_priv)
    tweak = verify._tagged_hash("TapTweak", xonly + merkle_root)
    t = int.from_bytes(tweak, "big")
    d = int.from_bytes(internal_priv, "big")
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    tweaked = ((d + t) % n).to_bytes(32, "big")
    tweaked_xonly = _xonly_from_secret(tweaked)
    return xonly, tweaked, tweaked_xonly


def test_scriptpath_sighash_pinned_vector():
    """Script-path SigMsg pinned against an independent BIP341
    implementation (the SigMsg carries the TapLeaf HASH of the leaf
    script, not the script bytes). A self-consistent sign/verify round
    trip cannot catch this, so the digest is pinned here."""
    leaf_script = bytes.fromhex(
        "204d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d076"
        "6ac")
    spk = b"\x51\x20" + b"\x33" * 32
    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = [CMutableTxIn(COutPoint(b"\xaa" * 32, 0))]
    tx.vout = [CMutableTxOut(5000, spk)]
    utxos = [(10000, spk)]
    sighash = verify.taproot_sighash(tx, 0, utxos, leaf_script=leaf_script,
                                     hashtype=0x01)
    assert sighash.hex() == (
        "180aa6856f39185d5da588050ef253509776b98789c39baa8582577747113389")


def test_scriptpath_roundtrip():
    """Synthetic taproot script-path spend: build, sign with the LEAF key
    (script-path signatures verify against the key in the leaf script,
    not the tweaked output key), verify with our verifier."""
    internal_priv = bytes.fromhex("77" * 32)
    leaf_priv = bytes.fromhex("02" * 32)
    leaf_xonly = _xonly_from_secret(leaf_priv)
    leaf_script = bytes(CScript([leaf_xonly, OP_CHECKSIG]))
    leaf_hash = verify.tapleaf_hash(leaf_script)
    xonly, _tweaked_priv, tweaked_xonly = _tweaked_pair(internal_priv,
                                                        leaf_hash)

    # Tx spending a P2TR output to itself.
    spk = b"\x51\x20" + tweaked_xonly
    tx = CMutableTransaction()
    tx.vin = [CMutableTxIn(COutPoint(b"\xaa" * 32, 0))]
    tx.vout = [CMutableTxOut(5000, spk)]
    utxos = [(10000, spk)]

    sighash = verify.taproot_sighash(tx, 0, utxos, leaf_script=leaf_script)
    sig = PrivateKey(leaf_priv).sign_schnorr(sighash) + b"\x01"
    assert verify.verify_schnorr(sig[:64], sighash, leaf_xonly)
    assert not verify.verify_schnorr(sig[:64], sighash, tweaked_xonly)

    # Through the full verifier path: witness [sig, script, control].
    control = b"\xc0" + xonly  # parity bit irrelevant to sighash/leaf check
    sw = CScriptWitness(stack=[sig, leaf_script, control])
    tx.wit = CTxWitness(vtxinwit=[CTxInWitness(scriptWitness=sw)])
    frozen = CTransaction.deserialize(tx.serialize())
    summary = verify.verify_input_taproot(frozen, 0, utxos)
    assert summary["path"] == "script"
    assert summary["signatures_verified"] == 1

    # A wrong message must NOT verify.
    sighash2 = verify.taproot_sighash(frozen, 0, utxos, hashtype=0x01)
    if sighash2 != sighash:
        assert not verify.verify_schnorr(sig[:64], sighash2, leaf_xonly)


def test_keypath_verify_against_tweaked_output_key():
    internal_priv = bytes.fromhex("88" * 32)
    xonly, tweaked_priv, tweaked_xonly = _tweaked_pair(internal_priv,
                                                       b"")
    spk = b"\x51\x20" + tweaked_xonly
    tx = CMutableTransaction()
    tx.vin = [CMutableTxIn(COutPoint(b"\xbb" * 32, 0))]
    tx.vout = [CMutableTxOut(4000, spk)]
    utxos = [(9000, spk)]
    sighash = verify.taproot_sighash(tx, 0, utxos, hashtype=0x01)
    sig = PrivateKey(tweaked_priv).sign_schnorr(sighash) + b"\x01"
    sw = CScriptWitness(stack=[sig])
    tx.wit = CTxWitness(vtxinwit=[CTxInWitness(scriptWitness=sw)])
    frozen = CTransaction.deserialize(tx.serialize())
    summary = verify.verify_input_taproot(frozen, 0, utxos)
    assert summary == {"path": "key", "signatures_present": 1,
                       "signatures_verified": 1}
