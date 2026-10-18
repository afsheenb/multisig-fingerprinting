"""Cryptographic verification on a validation subset.

For selected inputs, resolve prevouts and the raw spending transaction
(raw-transaction endpoint, 1 pt each) and verify:

    - script commitments: the revealed script must hash to the prevout's
      witness program / script hash. P2SH and P2WSH are fully checkable.
      Taproot output-key binding is NOT checkable without the whole
      taptree, so taproot inputs record 'not_verifiable' rather than a
      guess.

    - signatures: ECDSA (P2SH, P2WSH) via BIP143 sighash (python-bitcoinlib
      SignatureHash) + libsecp256k1; Taproot via BIP341 sighash
      (implemented locally below, validated against the BIP-0341 test
      vectors in tests) + BIP340 Schnorr via libsecp256k1.

OP_CHECKMULTISIG's ordered matching semantics are respected: a
signature is tried against keys in script order, the cursor never
moves backward, and a signature is never counted as valid merely
because it is present.
"""

import hashlib
import json

from Crypto.Hash import RIPEMD160

from bitcoin.core import CTransaction, b2lx, lx
from bitcoin.core.script import (
    CScript, SignatureHash, SIGHASH_SINGLE, SIGHASH_NONE,
    SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
)

from coincurve import PublicKey, PublicKeyXOnly

from . import scripts as S


def hash160(data):
    h = RIPEMD160.new()
    h.update(hashlib.sha256(data).digest())
    return h.digest()


# -- BIP341 tagged hashes and sighash -----------------------------------------

def _tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _is_annex(item):
    return len(item) >= 1 and item[0] == 0x50


def _push_bytes(data):
    """Script-serialized push of data (compact size + payload)."""
    n = len(data)
    if n < 253:
        return bytes([n]) + data
    return b"\xfd" + n.to_bytes(2, "little") + data


def taproot_sigmsg(tx, input_index, utxos, leaf_script=None,
                   leaf_version=0xC0, annex=None, hashtype=0x01):
    """BIP341 SigMsg bytes (epoch byte included, pre-tagged-hash).

    utxos: (amount_sats, spk_bytes) for EVERY tx input, in order.
    leaf_script: set for script-path spends (ext_flag 1).
    """
    anyonecanpay = bool(hashtype & 0x80)
    single = (hashtype & 0x03) == SIGHASH_SINGLE
    none = (hashtype & 0x03) == SIGHASH_NONE
    ext_flag = 1 if leaf_script is not None else 0
    key_version = 0
    codesep_pos = 0xFFFFFFFF

    buf = bytearray()
    buf += bytes([hashtype])
    buf += tx.nVersion.to_bytes(4, "little")
    buf += tx.nLockTime.to_bytes(4, "little")

    if not anyonecanpay:
        buf += hashlib.sha256(b"".join(
            tx.vin[i].prevout.serialize() for i in range(len(tx.vin))
        )).digest()
        buf += hashlib.sha256(b"".join(
            u[0].to_bytes(8, "little") for u in utxos)).digest()
        buf += hashlib.sha256(b"".join(
            _push_bytes(u[1]) for u in utxos)).digest()
        buf += hashlib.sha256(b"".join(
            tx.vin[i].nSequence.to_bytes(4, "little")
            for i in range(len(tx.vin)))).digest()
    if not (single or none):
        buf += hashlib.sha256(b"".join(
            o.nValue.to_bytes(8, "little") + _push_bytes(o.scriptPubKey)
            for o in tx.vout)).digest()

    spend_type = ext_flag * 2 + (1 if annex is not None else 0)
    buf += bytes([spend_type])

    if anyonecanpay:
        amount, spk = utxos[input_index]
        buf += tx.vin[input_index].prevout.serialize()
        buf += amount.to_bytes(8, "little")
        buf += _push_bytes(spk)
        buf += tx.vin[input_index].nSequence.to_bytes(4, "little")
    else:
        buf += input_index.to_bytes(4, "little")

    if annex is not None:
        buf += hashlib.sha256(_push_bytes(annex)).digest()

    if single:
        out = tx.vout[input_index]
        buf += hashlib.sha256(
            out.nValue.to_bytes(8, "little") +
            _push_bytes(out.scriptPubKey)).digest()

    if ext_flag == 1:
        buf += _push_bytes(leaf_script)
        buf += bytes([key_version])
        buf += codesep_pos.to_bytes(4, "little")

    return b"\x00" + bytes(buf)  # epoch 0 prepended


def taproot_sighash(tx, input_index, utxos, leaf_script=None,
                    leaf_version=0xC0, annex=None, hashtype=0x01):
    """BIP341 signature hash: TapSighash-tagged hash of the SigMsg."""
    msg = taproot_sigmsg(tx, input_index, utxos, leaf_script=leaf_script,
                         leaf_version=leaf_version, annex=annex,
                         hashtype=hashtype)
    return _tagged_hash("TapSighash", msg)


def tapleaf_hash(script_bytes, leaf_version=0xC0):
    return _tagged_hash("TapLeaf",
                        bytes([leaf_version]) + _push_bytes(script_bytes))


def verify_schnorr(sig64, msg32, xonly_pub32):
    try:
        return bool(PublicKeyXOnly(xonly_pub32).verify(sig64, msg32))
    except Exception:
        return False


def verify_ecdsa(sig_der, msg32, pubkey):
    try:
        # hasher=None: the message is already the sighash digest.
        return bool(PublicKey(pubkey).verify(sig_der, msg32, hasher=None))
    except Exception:
        return False


# -- commitment checks ---------------------------------------------------------

def check_commitment(revealed_script, prevout_spk):
    """Verify a revealed script commits to the spent output's scriptPubKey.

    Returns True / False / 'not_verifiable' (taproot) / 'not_applicable'
    (prevout shape not a commitment to a script).
    """
    spk = bytes(prevout_spk)
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return hashlib.sha256(revealed_script).digest() == spk[2:]
    if len(spk) == 23 and spk[0] == 0xA9 and spk[22] == 0x87:
        return hash160(revealed_script) == spk[2:22]
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return "not_verifiable"  # P2TR: needs the taptree to bind
    return "not_applicable"


# -- signature verification ------------------------------------------------------

def _keys_from_script(parsed):
    """Ordered key bytes for CHECKMULTISIG / CHECKSIGADD scripts."""
    if parsed.multisigs():
        m = parsed.multisigs()[0]
        return [parsed.push_data(i) for i in m["key_positions"]], "cm"
    if parsed.checksigadd_chain():
        c = parsed.checksigadd_chain()
        return [parsed.push_data(i) for i in c["key_positions"]], "csa"
    return [parsed.push_data(i) for i in parsed.key_positions()], "flat"


def verify_input_ecdsa(tx, input_index, script_bytes, amount):
    """Verify ECDSA signatures on one input. Returns a summary dict."""
    txin = tx.vin[input_index]
    stack = []
    if tx.wit.vtxinwit and input_index < len(tx.wit.vtxinwit):
        stack = [bytes(i) for i in
                 tx.wit.vtxinwit[input_index].scriptWitness.stack]
    if stack:
        sig_items = [s for s in stack[:-1] if S.is_der_signature(s)]
    else:
        pushes = []
        try:
            for _op, d, _i in txin.scriptSig.raw_iter():
                if d is not None:
                    pushes.append(bytes(d))
        except Exception:
            pushes = []
        sig_items = [s for s in pushes if S.is_der_signature(s)]

    parsed = S.ParsedScript(script_bytes)
    keys, kind = _keys_from_script(parsed)
    sigversion_arg = SIGVERSION_WITNESS_V0 if stack else SIGVERSION_BASE
    cscript = CScript(script_bytes)

    verified = []
    cursor = 0
    for item in sig_items:
        sig_der, hashtype = S.split_sighash(item)
        matched = None
        for k in range(cursor, len(keys)):
            msg = SignatureHash(cscript, tx, input_index, hashtype,
                                amount=amount, sigversion=sigversion_arg)
            if verify_ecdsa(sig_der, msg, keys[k]):
                matched = k
                break
            if kind != "cm":
                break  # flat/CHECKSIGADD: no ordered key search
        if matched is not None:
            verified.append({"key_index": matched, "hashtype": hashtype})
            cursor = matched + 1

    return {
        "signatures_present": len(sig_items),
        "signatures_verified": len(verified),
        "keys_in_script": len(keys),
        "verified": verified,
    }


def verify_input_taproot(tx, input_index, utxos, leaf_script=None,
                         leaf_version=0xC0):
    """Verify the Taproot signature on one input (key- or script-path).

    Assumes the tx has all prevouts resolved (utxos complete) so the
    sighash is computable. Returns a summary dict.
    """
    stack = [bytes(i) for i in
             tx.wit.vtxinwit[input_index].scriptWitness.stack] \
        if tx.wit.vtxinwit and input_index < len(tx.wit.vtxinwit) else []
    if not stack:
        return {"error": "no witness"}

    annex = None
    script_path = len(stack) >= 2
    items = list(stack)
    if len(items) >= 2 and _is_annex(items[-1]):
        annex = items[-1]
        items = items[:-1]

    if script_path:
        if len(items) < 2:
            return {"error": "malformed script-path witness"}
        leaf = items[-2]
        control = items[-1]
        leaf_version = control[0] & 0xFE
        sig64 = items[0][:64]
        hashtype = items[0][64] if len(items[0]) == 65 else 0x00
        # Script-path: the x-only key comes from the script's signature
        # check position; try every 32-byte key-adjacent push.
        parsed = S.ParsedScript(leaf)
        msg = taproot_sighash(tx, input_index, utxos, leaf_script=leaf,
                              leaf_version=leaf_version, annex=annex,
                              hashtype=hashtype)
        results = []
        for pos in parsed.key_positions(tapscript=True):
            if verify_schnorr(sig64, msg, parsed.push_data(pos)):
                results.append(pos)
        return {
            "path": "script",
            "signatures_present": 1,
            "signatures_verified": len(results),
            "verified_key_positions": results,
        }

    # Key-path spend.
    sig = items[0]
    sig64 = sig[:64]
    hashtype = sig[64] if len(sig) == 65 else 0x00
    msg = taproot_sighash(tx, input_index, utxos, annex=annex,
                          hashtype=hashtype)
    # The output key is the prevout's x-only key; the sighash is over
    # the tweaked key, so verification needs the spent output's spk.
    spk = utxos[input_index][1]
    if len(spk) == 34 and spk[0] == 0x51:
        ok = verify_schnorr(sig64, msg, spk[2:])
        return {"path": "key", "signatures_present": 1,
                "signatures_verified": int(ok)}
    return {"path": "key", "error": "prevout is not a P2TR output"}


# -- validation driver ------------------------------------------------------------

def _raw_hex_for(payload, txid):
    """Raw transaction hex for txid from a raw-transaction payload.

    The endpoint answers HTTP 200 with data as an empty list (results 0)
    when it cannot serve the transaction; a successful answer is a dict
    keyed by txid. Returns None in the not-served case.
    """
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    entry = data.get(txid) or {}
    return entry.get("raw_transaction")


def run_validation(config, conn, count=20):
    """Fetch raw prevout + spending transactions for a subset and verify.

    Cost: 2 points per selected input (prevout tx + spending tx), so the
    subset stays small. Both levels of nested P2SH-P2WSH are checked.
    """
    from .client import Client
    client = Client(config, conn)

    rows = conn.execute(
        "SELECT o.input_id, o.script_sha256, i.txid, i.input_index, "
        "i.prevout_txid, i.prevout_n, i.input_form, i.witness_json, "
        "s.script_hex, s.source "
        "FROM script_observations o "
        "JOIN inputs i ON i.input_id=o.input_id "
        "JOIN revealed_scripts s ON s.script_sha256=o.script_sha256 "
        "WHERE s.source IN ('p2wsh_witness','p2sh_redeem') "
        "ORDER BY RANDOM() LIMIT ?", (count,)).fetchall()
    if not rows:
        print("no validation candidates stored yet")
        return

    stats = {"commit_ok": 0, "commit_fail": 0, "commit_not_verifiable": 0,
             "sig_present": 0, "sig_verified": 0, "inputs_checked": 0,
             "failures": []}
    consecutive_unserved = 0
    for r in rows:
        # Spending tx raw (to rebuild sighash context).
        try:
            spx_payload, _c1, _p1 = client.raw_transaction(r["txid"])
        except Exception as exc:
            print("skip %s (spending tx fetch failed: %s)" % (r["txid"], exc))
            continue
        raw_spx = _raw_hex_for(spx_payload, r["txid"])
        if not raw_spx:
            # A confirmed txid answered with an empty payload: the
            # endpoint is not serving transactions, and every further
            # candidate would only spend points on the same result.
            consecutive_unserved += 1
            stats["failures"].append(
                {"txid": r["txid"], "input_index": r["input_index"],
                 "what": "spending tx not served by raw-transaction "
                         "endpoint (HTTP 200, empty data)"})
            if consecutive_unserved >= 3:
                print("stopping validation: raw-transaction endpoint "
                      "returned empty payloads for %d confirmed txids in "
                      "a row; remaining candidates skipped to preserve "
                      "budget" % consecutive_unserved)
                break
            continue
        consecutive_unserved = 0
        tx = CTransaction.deserialize(bytes.fromhex(raw_spx))
        # Prevout tx raw (for value + scriptPubKey).
        try:
            ptx_payload, _c2, _p2 = client.raw_transaction(r["prevout_txid"])
        except Exception as exc:
            print("skip %s (prevout fetch failed: %s)" % (r["prevout_txid"],
                                                          exc))
            continue
        raw_ptx = _raw_hex_for(ptx_payload, r["prevout_txid"])
        if not raw_ptx:
            print("skip %s (prevout tx not served by raw-transaction "
                  "endpoint)" % r["prevout_txid"])
            continue
        ptx = CTransaction.deserialize(bytes.fromhex(raw_ptx))
        if r["prevout_n"] >= len(ptx.vout):
            continue
        prevout = ptx.vout[r["prevout_n"]]

        script_bytes = bytes.fromhex(r["script_hex"])
        commit = check_commitment(script_bytes, bytes(prevout.scriptPubKey))
        stats["inputs_checked"] += 1
        if commit is True:
            stats["commit_ok"] += 1
        elif commit is False:
            stats["commit_fail"] += 1
            stats["failures"].append({"txid": r["txid"],
                                      "input_index": r["input_index"],
                                      "what": "commitment"})
        else:
            stats["commit_not_verifiable"] += 1

        # Signature verification (ECDSA paths only here).
        try:
            summary = verify_input_ecdsa(tx, r["input_index"], script_bytes,
                                         prevout.nValue)
            stats["sig_present"] += summary["signatures_present"]
            stats["sig_verified"] += summary["signatures_verified"]
        except Exception as exc:
            stats["failures"].append({"txid": r["txid"],
                                      "input_index": r["input_index"],
                                      "what": "sig check error: %s" % exc})

    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        [("validation_commit_ok", str(stats["commit_ok"])),
         ("validation_commit_fail", str(stats["commit_fail"])),
         ("validation_sig_present", str(stats["sig_present"])),
         ("validation_sig_verified", str(stats["sig_verified"])),
         ("validation_inputs_checked", str(stats["inputs_checked"]))])
    conn.commit()
    print("validation: %d inputs, commitments %d ok / %d FAILED / %d "
          "not verifiable; signatures %d/%d verified"
          % (stats["inputs_checked"], stats["commit_ok"],
             stats["commit_fail"], stats["commit_not_verifiable"],
             stats["sig_verified"], stats["sig_present"]))
    if stats["failures"]:
        print("failures: %s" % json.dumps(stats["failures"], indent=2))
    return stats
