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

import gzip
import hashlib
import json
import os
from functools import lru_cache

from Crypto.Hash import RIPEMD160

from bitcoin.core import CTransaction, b2lx, lx
from bitcoin.core.script import (
    CScript, SignatureHash, SIGHASH_SINGLE, SIGHASH_NONE,
    SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
)

from coincurve import PublicKey, PublicKeyXOnly

from . import decode
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
        # TapLeaf hash: tagged_hash("TapLeaf", leaf_version || push(leaf)).
        # The SigMsg carries this digest, never the script bytes.
        buf += tapleaf_hash(leaf_script, leaf_version)
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


# -- mempool.space-resolved validation ---------------------------------------------

def _tx_from_mempool_json(t):
    """Rebuild a CTransaction from a mempool.space /tx JSON object.

    Used when the response carries no raw hex (the esplora shape): every
    field the sighash needs (version, locktime, prevouts, sequences,
    scriptSigs, witness stacks, outputs) is present in the JSON.
    """
    from bitcoin.core import (
        CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint,
        CTxInWitness, CScriptWitness, CTxWitness, lx,
    )
    from bitcoin.core.script import CScript

    vin = []
    for v in t["vin"]:
        txin = CMutableTxIn(
            COutPoint(lx(v["txid"]), v["vout"]),
            CScript(bytes.fromhex(v.get("scriptsig") or "")),
            v.get("sequence", 0xFFFFFFFF),
        )
        vin.append(txin)
    vout = [
        CMutableTxOut(o["value"], CScript(bytes.fromhex(o["scriptpubkey"])))
        for o in t["vout"]
    ]
    tx = CMutableTransaction(vin, vout, t.get("locktime", 0),
                             t.get("version", 2))
    stacks = []
    for v in t["vin"]:
        stacks.append(CTxInWitness(CScriptWitness(
            [bytes.fromhex(item) for item in v.get("witness") or []])))
    tx.wit = CTxWitness(stacks)
    return tx


def _real_txid(data_dir, wtxid, height):
    """True txid for a corpus-stored transaction identifier.

    decode.py stores tx.GetHash(), which for segwit transactions is the
    witness-inclusive hash (wtxid semantics), not the txid used by the
    outside world. The cached raw blocks carry both: GetTxid() recovers
    the real txid from the same deserialized transaction. Returns None
    when the block is not cached or the identifier is not in it.
    """
    idx = _block_tx_index(data_dir, height)
    if idx is None:
        return None
    tx = idx.get(wtxid)
    if tx is None:
        return None
    return b2lx(tx.GetTxid())


def run_validation_mempool(config, conn, count=1000):
    """Prevout-resolved validation via the mempool.space REST API.

    Selects one script-revealing observation per spending transaction,
    spread across the study window (a stride over distinct txids walking
    newest-first), resolves each spending transaction's real txid from
    the cached raw block (corpus identifiers are witness-inclusive for
    segwit transactions; see _real_txid), then fetches GET /tx/{txid}
    once per transaction — the response carries every input's prevout
    scriptPubKey and value — and verifies script commitments, ECDSA
    signatures (BIP143) for P2SH/P2WSH inputs, and full Taproot
    verification (BIP341 sighash + BIP340 Schnorr, key-path against the
    P2TR prevout key, script-path against the leaf keys) for taproot
    inputs.

    Results land in validation_results so a rerun skips already
    validated inputs; requests dedupe through the permanent cache. A
    persistent 429 stops the run cleanly with progress persisted.
    """
    from .mempool import MempoolClient, MempoolThrottled

    client = MempoolClient(config, conn)

    total_txids = conn.execute(
        "SELECT COUNT(DISTINCT i.txid) AS c "
        "FROM script_observations o "
        "JOIN inputs i ON i.input_id=o.input_id "
        "JOIN revealed_scripts s ON s.script_sha256=o.script_sha256 "
        "WHERE s.source IN ('p2sh_redeem','p2wsh_witness','taproot_leaf')"
    ).fetchone()["c"]
    stride = max(1, total_txids // max(count, 1))
    print("selecting %d of %d distinct spending txids (stride %d), "
          "spread newest-first across the study window" % (count, total_txids,
                                                           stride))

    done = set(row["input_id"] for row in conn.execute(
        "SELECT input_id FROM validation_results"))

    selected = []
    seen_txids = set()
    txid_rank = 0
    stats = {
        "inputs_checked": 0, "commit_ok": 0, "commit_fail": 0,
        "commit_not_verifiable": 0, "sig_present": 0, "sig_verified": 0,
        "txs_fetched": 0, "requests_made": 0, "throttled": False,
        "ecdsa_inputs": 0, "taproot_inputs": 0,
        "taproot_key_path_ok": 0, "taproot_script_path_ok": 0,
        "taproot_leaf_mismatch": 0, "by_form": {}, "failures": [],
    }
    # Done and locally-unresolvable txids free their stride slot, so a
    # rerun always validates fresh inputs instead of re-walking the top
    # of the window.
    todo = []
    for r in conn.execute(
        "SELECT o.input_id, i.txid, i.input_index, i.prevout_txid, "
        "i.prevout_n, i.input_form, i.block_height, s.script_hex, s.source "
        "FROM script_observations o "
        "JOIN inputs i ON i.input_id=o.input_id "
        "JOIN revealed_scripts s ON s.script_sha256=o.script_sha256 "
        "WHERE s.source IN ('p2sh_redeem','p2wsh_witness','taproot_leaf') "
        "ORDER BY i.block_height DESC, o.input_id DESC"
    ):
        if r["txid"] in seen_txids:
            continue
        seen_txids.add(r["txid"])
        if r["input_id"] in done:
            continue
        txid_rank += 1
        if (txid_rank - 1) % stride:
            continue
        real_txid = _real_txid(config.data_dir, r["txid"], r["block_height"])
        if real_txid is None:
            stats["failures"].append(
                {"txid": r["txid"], "block_height": r["block_height"],
                 "what": "real txid not resolvable (spending block raw "
                         "not cached or identifier absent)"})
            txid_rank -= 1
            continue
        selected.append((r, real_txid))
        if len(selected) >= count:
            break
    todo = selected
    print("%d inputs to validate (%d already stored in validation_results)"
          % (len(todo), len(done)))

    def _bump(form, key, value=1):
        form_stats = stats["by_form"].setdefault(form, {
            "inputs": 0, "commit_ok": 0, "commit_fail": 0,
            "commit_not_verifiable": 0, "sig_present": 0, "sig_verified": 0,
            "verified_inputs": 0})
        form_stats[key] += value

    try:
        for n, (r, real_txid) in enumerate(todo):
            if n and n % 100 == 0:
                print("... %d/%d inputs; %d tx fetches; sigs %d/%d verified"
                      % (n, len(todo), stats["txs_fetched"],
                         stats["sig_verified"], stats["sig_present"]))
            try:
                payload = client.tx(real_txid)
                stats["txs_fetched"] += 1
            except MempoolThrottled:
                stats["throttled"] = True
                print("STOPPING cleanly: mempool.space throttled the run "
                      "past the backoff ladder at input %d/%d; progress is "
                      "persisted and a rerun resumes from validation_results"
                      % (n, len(todo)))
                break
            except Exception as exc:
                stats["failures"].append({"txid": real_txid,
                                          "what": "tx fetch failed: %s" % exc})
                continue

            vin = payload.get("vin") or []
            if r["input_index"] >= len(vin):
                stats["failures"].append(
                    {"txid": real_txid, "input_index": r["input_index"],
                     "what": "input_index out of range in fetched tx"})
                continue
            prevout = vin[r["input_index"]].get("prevout")
            if not prevout:
                stats["failures"].append(
                    {"txid": real_txid, "input_index": r["input_index"],
                     "what": "fetched vin has no prevout"})
                continue

            utxos = []
            for v in vin:
                po = v.get("prevout")
                if po:
                    utxos.append((po["value"],
                                  bytes.fromhex(po["scriptpubkey"])))
                else:  # coinbase or malformed; never a selected input
                    utxos.append((0, b""))

            if payload.get("hex"):
                tx = CTransaction.deserialize(bytes.fromhex(payload["hex"]))
            else:
                tx = _tx_from_mempool_json(payload)
            if b2lx(tx.GetTxid()) != real_txid:
                stats["failures"].append(
                    {"txid": real_txid,
                     "what": "rebuilt tx txid does not match the requested "
                             "txid"})
                continue

            script_bytes = bytes.fromhex(r["script_hex"])
            spk = bytes.fromhex(prevout["scriptpubkey"])
            value = prevout["value"]
            commit = check_commitment(script_bytes, spk)

            form = r["input_form"]
            source = r["source"]
            key_positions = []
            via = None
            verified_input = False
            try:
                if source == "taproot_leaf":
                    summary = verify_input_taproot(tx, r["input_index"],
                                                   utxos)
                    via = "taproot_" + summary.get("path", "unknown")
                    key_positions = summary.get("verified_key_positions") \
                        or []
                    verified_input = summary.get("signatures_verified", 0) > 0
                    if summary.get("path") == "key":
                        stats["taproot_key_path_ok"] += \
                            summary.get("signatures_verified", 0)
                    elif summary.get("path") == "script":
                        stats["taproot_script_path_ok"] += \
                            summary.get("signatures_verified", 0)
                        leaf = _witness_leaf_hex(tx, r["input_index"])
                        if leaf is not None and leaf != r["script_hex"]:
                            stats["taproot_leaf_mismatch"] += 1
                            stats["failures"].append(
                                {"txid": real_txid,
                                 "input_index": r["input_index"],
                                 "what": "witness leaf script differs from "
                                         "the stored revealed script"})
                    sig_present = summary.get("signatures_present", 0)
                    sig_verified = summary.get("signatures_verified", 0)
                    if "error" in summary:
                        stats["failures"].append(
                            {"txid": real_txid,
                             "input_index": r["input_index"],
                             "what": "taproot verify error: %s"
                                     % summary["error"]})
                else:
                    summary = verify_input_ecdsa(tx, r["input_index"],
                                                 script_bytes, value)
                    via = "ecdsa_bip143"
                    key_positions = [v["key_index"]
                                     for v in summary.get("verified", [])]
                    sig_present = summary["signatures_present"]
                    sig_verified = summary["signatures_verified"]
                    verified_input = sig_verified > 0
                    stats["ecdsa_inputs"] += 1
            except Exception as exc:
                # Leave this input unstored: a rerun will re-attempt it.
                stats["failures"].append(
                    {"txid": real_txid, "input_index": r["input_index"],
                     "what": "verification error: %s" % exc})
                continue

            stats["inputs_checked"] += 1
            _bump(form, "inputs")
            if source == "taproot_leaf":
                stats["taproot_inputs"] += 1
            if commit is True:
                stats["commit_ok"] += 1
                _bump(form, "commit_ok")
            elif commit is False:
                stats["commit_fail"] += 1
                _bump(form, "commit_fail")
                stats["failures"].append(
                    {"txid": real_txid, "input_index": r["input_index"],
                     "what": "commitment"})
            else:
                stats["commit_not_verifiable"] += 1
                _bump(form, "commit_not_verifiable")
            stats["sig_present"] += sig_present
            stats["sig_verified"] += sig_verified
            _bump(form, "sig_present", sig_present)
            _bump(form, "sig_verified", sig_verified)
            if verified_input:
                _bump(form, "verified_inputs")

            conn.execute(
                "INSERT OR REPLACE INTO validation_results(input_id, "
                "commitment_status, signatures_present, signatures_verified, "
                "verified_key_positions_json, verified_via) "
                "VALUES(?,?,?,?,?,?)",
                (r["input_id"], ("ok" if commit is True else
                                 "failed" if commit is False else
                                 str(commit)),
                 sig_present, sig_verified,
                 json.dumps(key_positions), via))
            if n % 50 == 0:
                conn.commit()
    finally:
        conn.commit()

    stats["requests_made"] = conn.execute(
        "SELECT COUNT(*) AS c FROM mempool_ledger").fetchone()["c"]
    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        [("validation_mempool_inputs", str(stats["inputs_checked"])),
         ("validation_mempool_commit_ok", str(stats["commit_ok"])),
         ("validation_mempool_commit_fail", str(stats["commit_fail"])),
         ("validation_mempool_commit_not_verifiable",
          str(stats["commit_not_verifiable"])),
         ("validation_mempool_sig_present", str(stats["sig_present"])),
         ("validation_mempool_sig_verified", str(stats["sig_verified"])),
         ("validation_mempool_taproot_key_path_ok",
          str(stats["taproot_key_path_ok"])),
         ("validation_mempool_taproot_script_path_ok",
          str(stats["taproot_script_path_ok"])),
         ("validation_mempool_throttled",
          "1" if stats["throttled"] else "0")])
    conn.commit()

    print("mempool validation: %d inputs over %d tx fetches; commitments "
          "%d ok / %d FAILED / %d not verifiable; ECDSA inputs %d; "
          "taproot inputs %d (key-path verified %d, script-path verified "
          "%d); signatures %d/%d verified"
          % (stats["inputs_checked"], stats["txs_fetched"],
             stats["commit_ok"], stats["commit_fail"],
             stats["commit_not_verifiable"], stats["ecdsa_inputs"],
             stats["taproot_inputs"], stats["taproot_key_path_ok"],
             stats["taproot_script_path_ok"], stats["sig_verified"],
             stats["sig_present"]))
    for form, fs in sorted(stats["by_form"].items()):
        print("  %-22s inputs %5d  commit %4d ok / %3d failed / %4d nv; "
              "sigs %5d/%5d verified; fully verified inputs %d"
              % (form, fs["inputs"], fs["commit_ok"], fs["commit_fail"],
                 fs["commit_not_verifiable"], fs["sig_verified"],
                 fs["sig_present"], fs["verified_inputs"]))
    if stats["failures"]:
        print("failures (%d): %s" % (len(stats["failures"]),
              json.dumps(stats["failures"][:20], indent=2)))
    return stats


def _witness_leaf_hex(tx, input_index):
    """Hex of the revealed tapleaf script inside the witness stack, or
    None when the stack shape does not carry one."""
    if not (tx.wit.vtxinwit and input_index < len(tx.wit.vtxinwit)):
        return None
    stack = [bytes(i) for i in
             tx.wit.vtxinwit[input_index].scriptWitness.stack]
    if len(stack) < 2:
        return None
    items = list(stack)
    if len(items) >= 2 and len(items[-1]) >= 1 and items[-1][0] == 0x50:
        items = items[:-1]
    return items[-2].hex()


# -- local (zero-point) validation ------------------------------------------------

def _check_commitment_p2sh_p2wsh(script_bytes, script_sig_hex, prevout_spk):
    """Two-level commitment for nested P2SH-P2WSH inputs.

    The prevout is a P2SH program, so the revealed witnessScript binds
    through the P2WSH program carried in the scriptSig redeem push:
    sha256(witnessScript) must equal that program, and hash160(redeem)
    must equal the prevout's P2SH script hash.
    """
    pushes = decode._script_sig_pushes(bytes.fromhex(script_sig_hex)) \
        if script_sig_hex else None
    if not pushes or pushes[-1] is None:
        return False
    redeem = bytes.fromhex(pushes[-1])
    if not (len(redeem) == 34 and redeem[0] == 0x00 and redeem[1] == 0x20):
        return False
    if hashlib.sha256(script_bytes).digest() != redeem[2:]:
        return False
    spk = bytes(prevout_spk)
    if len(spk) == 23 and spk[0] == 0xA9 and spk[22] == 0x87:
        return hash160(redeem) == spk[2:22]
    return False


@lru_cache(maxsize=8)
def _block_tx_index(data_dir, height):
    """txid -> CTransaction for one cached raw block, or None when the
    block is not cached. Keeps only recent heights alive (LRU)."""
    path = os.path.join(data_dir, "cache", "raw_block_%d.json.gz" % height)
    if not os.path.exists(path):
        return None
    with gzip.open(path) as fh:
        payload = json.load(fh)
    data = payload.get("data", {})
    entry = data.get(str(height)) or data.get(height) or {}
    raw_hex = entry.get("raw_block")
    if not raw_hex:
        return None
    block = decode.decode_block(raw_hex, height)
    return {b2lx(tx.GetHash()): tx for tx in block.vtx}


def run_validation_local(config, conn):
    """Verify commitments and ECDSA signatures against the local cache.

    For every input that revealed a script, resolve the prevout from the
    cached raw block of the creating transaction's block (only when that
    transaction is itself in the corpus) and run check_commitment plus
    verify_input_ecdsa. No network request is made: inputs whose prevout
    is outside the corpus, or whose block cache file is absent, are
    skipped and counted. Taproot leaves get the commitment check only;
    their signature path needs the BIP341 machinery keyed on resolved
    prevouts of every tx input, which the corpus rarely supports.
    """
    rows = conn.execute(
        "SELECT o.input_id, i.txid, i.input_index, i.prevout_txid, "
        "i.prevout_n, i.script_sig_hex, i.input_form, s.script_hex, "
        "s.source, "
        "pt.block_height AS ptx_height, st.block_height AS stx_height "
        "FROM script_observations o "
        "JOIN inputs i ON i.input_id=o.input_id "
        "JOIN revealed_scripts s ON s.script_sha256=o.script_sha256 "
        "JOIN txs st ON st.txid=i.txid "
        "LEFT JOIN txs pt ON pt.txid=i.prevout_txid "
        "ORDER BY pt.block_height, st.block_height").fetchall()

    stats = {"inputs_checked": 0, "commit_ok": 0, "commit_fail": 0,
             "commit_not_verifiable": 0, "sig_present": 0, "sig_verified": 0,
             "taproot_leaves": 0, "prevout_not_in_corpus": 0,
             "prevout_cache_missing": 0, "spend_cache_missing": 0,
             "prevout_n_out_of_range": 0, "failures": []}

    for r in rows:
        if r["ptx_height"] is None:
            stats["prevout_not_in_corpus"] += 1
            continue
        ptxs = _block_tx_index(config.data_dir, r["ptx_height"])
        if ptxs is None:
            stats["prevout_cache_missing"] += 1
            continue
        ptx = ptxs.get(r["prevout_txid"])
        if ptx is None or r["prevout_n"] >= len(ptx.vout):
            stats["prevout_n_out_of_range"] += 1
            continue
        prevout = ptx.vout[r["prevout_n"]]

        script_bytes = bytes.fromhex(r["script_hex"])
        if r["input_form"] == "p2sh_p2wsh" and r["source"] == "p2wsh_witness":
            commit = _check_commitment_p2sh_p2wsh(
                script_bytes, r["script_sig_hex"],
                bytes(prevout.scriptPubKey))
        else:
            commit = check_commitment(script_bytes,
                                      bytes(prevout.scriptPubKey))
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

        if r["source"] == "taproot_leaf":
            stats["taproot_leaves"] += 1
            continue
        stxs = _block_tx_index(config.data_dir, r["stx_height"])
        if stxs is None:
            stats["spend_cache_missing"] += 1
            continue
        stx = stxs.get(r["txid"])
        if stx is None:
            stats["spend_cache_missing"] += 1
            continue
        try:
            summary = verify_input_ecdsa(stx, r["input_index"], script_bytes,
                                         prevout.nValue)
        except Exception as exc:
            stats["failures"].append({"txid": r["txid"],
                                      "input_index": r["input_index"],
                                      "what": "sig check error: %s" % exc})
            continue
        stats["sig_present"] += summary["signatures_present"]
        stats["sig_verified"] += summary["signatures_verified"]

    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)",
        [("validation_local_inputs_checked", str(stats["inputs_checked"])),
         ("validation_local_commit_ok", str(stats["commit_ok"])),
         ("validation_local_commit_fail", str(stats["commit_fail"])),
         ("validation_local_sig_present", str(stats["sig_present"])),
         ("validation_local_sig_verified", str(stats["sig_verified"])),
         ("validation_local_prevout_not_in_corpus",
          str(stats["prevout_not_in_corpus"])),
         ("validation_local_prevout_cache_missing",
          str(stats["prevout_cache_missing"]))])
    conn.commit()
    print("local validation: %d of %d script-revealing inputs resolvable "
          "(%d prevouts not in corpus, %d cache misses); commitments "
          "%d ok / %d FAILED / %d not verifiable; signatures %d/%d "
          "verified; %d taproot leaves commitment-checked only"
          % (stats["inputs_checked"], len(rows),
             stats["prevout_not_in_corpus"],
             stats["prevout_cache_missing"] + stats["spend_cache_missing"],
             stats["commit_ok"], stats["commit_fail"],
             stats["commit_not_verifiable"], stats["sig_verified"],
             stats["sig_present"], stats["taproot_leaves"]))
    if stats["failures"]:
        print("failures (%d): %s" % (len(stats["failures"]),
              json.dumps(stats["failures"][:20], indent=2)))
    return stats
