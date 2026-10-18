"""Raw block decoding and per-input extraction.

Blocks arrive as Blockchair hex strings and are decoded LOCALLY with
python-bitcoinlib; the provider's decoded JSON is never trusted. Every
transaction input in every block gets a record with its input form
(legacy P2SH, native P2WSH, nested P2SH-P2WSH, taproot key-path,
taproot script-path, P2WPKH, legacy, other), its raw scriptSig/witness,
and extracted signature metadata.

Unfamiliar structures are recorded as 'other', never dropped.
"""

import datetime
import json

from bitcoin.core import CBlock, CTransaction, b2lx
from bitcoin.core.script import CScript, CScriptInvalidError

from . import scripts as S

# Sighash byte values we name in reports.
SIGHASH_NAMES = {
    0x01: "ALL",
    0x02: "NONE",
    0x03: "SINGLE",
    0x81: "ANYONECANPAY|ALL",
    0x82: "ANYONECANPAY|NONE",
    0x83: "ANYONECANPAY|SINGLE",
    0x00: "DEFAULT",
}


def decode_block(raw_hex, height):
    """Decode a serialized block; returns (CBlock, txid-ordered list)."""
    raw = bytes.fromhex(raw_hex)
    block = CBlock.deserialize(raw)
    return block


def block_header(block):
    return {
        "hash": b2lx(block.GetHash()),
        "time": datetime.datetime.fromtimestamp(
            block.nTime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "n_tx": len(block.vtx),
    }


def _witness_stack(tx, idx):
    """Witness stack for input idx, or [] when absent."""
    wit = tx.wit
    if not wit.vtxinwit or idx >= len(wit.vtxinwit):
        return []
    return [bytes(item) for item in wit.vtxinwit[idx].scriptWitness.stack]


def _script_sig_pushes(script_sig):
    """Pushes of a scriptSig as hex list; None when unparsable."""
    try:
        return [bytes(d).hex() if d is not None else None
                for _op, d, _i in CScript(bytes(script_sig)).raw_iter()]
    except (CScriptInvalidError, ValueError):
        return None


def _looks_like_control_block(data):
    """33 + 32*k bytes with a leaf-version/parity high byte.

    Standard tapscript leaves use 0xC0/0xC1; the parity bit is the low
    bit, so accept the whole plausible version range but reject plain
    signature/pubkey shapes.
    """
    if len(data) < 33 or (len(data) - 33) % 32 != 0:
        return False
    return 0xC0 <= data[0] <= 0xFF


def _is_p2wsh_program_push(payload):
    """P2SH redeem script that is a segwit P2WSH program: 0020{32}."""
    return len(payload) == 34 and payload[0] == 0x00 and payload[1] == 0x20


def _sig_records(data, schnorr=False):
    """(sig_bytes_hex, sighash_type_name, is_schnorr) for one push."""
    if schnorr:
        if len(data) == 64:
            return data.hex(), SIGHASH_NAMES[0x00], True
        if len(data) == 65:
            return data[:-1].hex(), SIGHASH_NAMES.get(
                data[-1], "0x%02x" % data[-1]), True
        return None
    if S.is_der_signature(data):
        return data[:-1].hex(), SIGHASH_NAMES.get(
            data[-1], "0x%02x" % data[-1]), False
    return None


def extract_signatures(script_sig_pushes, witness, taproot=False):
    """Count and classify signatures in scriptSig pushes + witness stack."""
    sigs = []
    for hx in script_sig_pushes or []:
        if hx is None:
            continue
        rec = _sig_records(bytes.fromhex(hx))
        if rec:
            sigs.append(rec)
    n = len(witness)
    for i, item in enumerate(witness):
        # In taproot witnesses the last two items are leaf script and
        # control block; key-path sigs are the lone first item.
        if taproot and i >= n - 2 and n >= 2:
            continue
        if len(item) == 64 or (len(item) == 65 and item[-1] in
                               (0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00)):
            rec = _sig_records(item, schnorr=True)
            if rec:
                sigs.append(rec)
            continue
        rec = _sig_records(item)
        if rec:
            sigs.append(rec)
    return sigs


def classify_input(script_sig_hex, witness):
    """Determine the input form from a scriptSig + witness alone.

    Prevout scriptPubKeys are usually unknown at scan time (they live in
    the spending transaction's own history), so this is a best-effort
    form; commitment verification happens later against resolved prevouts.
    """
    pushes = None
    if script_sig_hex:
        pushes = _script_sig_pushes(bytes.fromhex(script_sig_hex))

    has_witness = bool(witness)
    taproot_control = has_witness and len(witness) >= 2 and \
        _looks_like_control_block(witness[-1])

    # Taproot script-path: last witness item is a control block.
    if taproot_control:
        return "taproot_scriptpath"
    # Taproot key-path: single (64/65-byte) Schnorr sig, optional annex.
    if has_witness and len(witness) in (1, 2) and len(witness[0]) in (64, 65) \
            and not (pushes and len(pushes) > 1):
        if len(witness) == 2 and not (witness[1] and witness[1][0] == 0x50):
            pass  # second item is not an annex; fall through
        else:
            return "taproot_keypath"
    # P2WPKH: [sig, pubkey].
    if has_witness and len(witness) == 2 and S.is_pubkey_data(witness[1]) \
            and S.is_der_signature(witness[0]):
        return "p2wpkh"
    # P2WSH / P2SH-P2WSH: witnessScript is the final witness item (BIP141);
    # the taproot case (script second-to-last) is handled above.
    if has_witness and len(witness) >= 2:
        script = witness[-1]
        if pushes and len(pushes) == 1 and pushes[0] is not None:
            payload = bytes.fromhex(pushes[0])
            if _is_p2wsh_program_push(payload):
                return "p2sh_p2wsh"
        if S.ParsedScript(script).has_sig_check():
            return "p2wsh"
        return "witness_other"
    # Legacy: scriptSig whose final push parses as a script.
    if pushes and len(pushes) >= 2:
        if pushes[-1] is None:
            return "legacy"
        try:
            redeem = bytes.fromhex(pushes[-1])
        except ValueError:
            return "legacy"
        # A P2PKH scriptSig also ends in a pubkey push; raw pubkey bytes
        # re-parsed as a script can accidentally contain a sig-check
        # opcode byte, so require a key shape OR a clean script parse.
        if S.is_pubkey_data(redeem):
            return "legacy"
        parsed = S.ParsedScript(redeem)
        if parsed.parse_error is None and parsed.has_sig_check():
            return "p2sh_redeem"
        return "legacy"
    return "legacy" if (script_sig_hex and not has_witness) else "other"


def extract_input_records(block, height):
    """One record per transaction input in the block."""
    block_time = datetime.datetime.fromtimestamp(
        block.nTime, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    records = []
    for tx in block.vtx:
        txid = b2lx(tx.GetHash())
        for idx, txin in enumerate(tx.vin):
            # Coinbase input has no meaningful script content.
            if txin.prevout.is_null():
                continue
            witness = _witness_stack(tx, idx)
            script_sig_hex = txin.scriptSig.hex() if txin.scriptSig else None
            form = classify_input(script_sig_hex, witness)
            taproot = form in ("taproot_scriptpath", "taproot_keypath")
            sigs = extract_signatures(
                _script_sig_pushes(bytes.fromhex(script_sig_hex))
                if script_sig_hex else None,
                witness, taproot=taproot)
            records.append({
                "txid": txid,
                "input_index": idx,
                "block_height": height,
                "block_time": block_time,
                "prevout_txid": b2lx(txin.prevout.hash),
                "prevout_n": txin.prevout.n,
                "sequence": txin.nSequence,
                "script_sig_hex": script_sig_hex,
                "witness_json": json.dumps([item.hex() for item in witness]),
                "input_form": form,
                "n_signatures": len(sigs),
                "sighash_types": json.dumps([s[1] for s in sigs]),
                "tx_version": tx.nVersion,
                "tx_locktime": tx.nLockTime,
                "n_tx_inputs": len(tx.vin),
                "n_tx_outputs": len(tx.vout),
            })
    return records


def revealed_script_for_input(record):
    """Return (source, raw_script_bytes) for inputs that reveal a script,
    else (None, None)."""
    form = record["input_form"]
    if form == "p2sh_redeem":
        pushes = _script_sig_pushes(bytes.fromhex(record["script_sig_hex"]))
        if pushes and pushes[-1] is not None:
            return "p2sh_redeem", bytes.fromhex(pushes[-1])
    elif form in ("p2wsh", "p2sh_p2wsh", "witness_other"):
        witness = [bytes.fromhex(hx)
                   for hx in json.loads(record["witness_json"])]
        if len(witness) >= 2:
            return "p2wsh_witness", witness[-1]
    elif form == "taproot_scriptpath":
        witness = [bytes.fromhex(hx)
                   for hx in json.loads(record["witness_json"])]
        if len(witness) >= 2:
            return "taproot_leaf", witness[-2]
    return None, None


def executed_branch(record):
    """For conditional policies: which branch the witness took.

    Miniscript-style layouts put boolean condition elements (empty
    string = false, single 0x01 = true) among the witness items; the
    last such element decides the branch. Returns 'true', 'false', or
    None when no boolean element is identifiable.
    """
    if record["input_form"] not in ("p2wsh", "p2sh_p2wsh",
                                    "taproot_scriptpath"):
        return None
    witness = [bytes.fromhex(hx) for hx in json.loads(record["witness_json"])]
    # Witness args sit before the script (P2WSH) or before script+control
    # block (taproot script-path).
    tail = 2 if record["input_form"] == "taproot_scriptpath" else 1
    args = witness[:-tail] if len(witness) > tail else witness
    booleans = [item for item in args if len(item) <= 1
                and not S.is_der_signature(item)]
    if not booleans:
        return None
    return "true" if booleans[-1] else "false"
