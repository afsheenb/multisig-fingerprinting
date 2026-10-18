"""Script classification, template fingerprinting, and key extraction.

A "revealed script" is a redeemScript (P2SH scriptSig), a witnessScript
(P2WSH / nested P2SH-P2WSH witness), or a revealed tapscript leaf
(Taproot script-path spend). This module turns raw script bytes into:

    L1  exact-script hash           sha256 of the raw bytes
    L2  key-normalized template     keys/signatures replaced, everything
                                    else (thresholds, timelock VALUES,
                                    branch structure) preserved
    L3  parameter-normalized        additionally replaces timelock values
        template                    and data pushes; thresholds and branch
                                    structure stay so families of the same
                                    policy shape group together
    L4  wallet family               rule-based category

Templates do not, by themselves, identify a commercial provider; that is
the attribution engine's job (see attribute.py).

Signature-position semantics: a CHECKMULTISIG's signatures map to keys
in order; a CHECKSIGADD chain's signature count matters, not positions.
Signature/key matching lives in verify.py, not here.
"""

import hashlib

from bitcoin.core.script import (
    CScript,
    CScriptInvalidError,
    CScriptTruncatedPushDataError,
    CScriptOp,
    OPCODE_NAMES,
)


def _op_name(op):
    return OPCODE_NAMES.get(op, "0x%02x" % int(op))

# Push ops we treat as small integers.
OP_0 = CScriptOp(0x00)
OP_1NEGATE = CScriptOp(0x4F)
OP_1 = CScriptOp(0x51)
OP_2 = CScriptOp(0x52)
OP_3 = CScriptOp(0x53)
OP_16 = CScriptOp(0x60)

OP_CHECKMULTISIG = CScriptOp(0xAE)
OP_CHECKMULTISIGVERIFY = CScriptOp(0xAF)
OP_CHECKSIG = CScriptOp(0xAC)
OP_CHECKSIGVERIFY = CScriptOp(0xAD)
OP_CHECKSIGADD = CScriptOp(0xBA)
OP_CHECKLOCKTIMEVERIFY = CScriptOp(0xB1)
OP_CHECKSEQUENCEVERIFY = CScriptOp(0xB2)
OP_IF = CScriptOp(0x63)
OP_NOTIF = CScriptOp(0x64)
OP_ELSE = CScriptOp(0x67)
OP_ENDIF = CScriptOp(0x68)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_EQUAL = CScriptOp(0x87)
OP_GREATERTHANOREQUAL = CScriptOp(0xA1)
OP_GREATERTHAN = CScriptOp(0xA0)
OP_NUMEQUAL = CScriptOp(0x9C)
OP_NUMEQUALVERIFY = CScriptOp(0x9D)
OP_LESSTHANOREQUAL = CScriptOp(0xA3)
OP_LESSTHAN = CScriptOp(0xA2)
OP_SHA256 = CScriptOp(0xA8)
OP_HASH160 = CScriptOp(0xA9)
OP_HASH256 = CScriptOp(0xAA)
OP_RIPEMD160 = CScriptOp(0xA6)
OP_DROP = CScriptOp(0x75)

SIG_CHECK_OPS = {OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD}
MULTISIG_CHECK_OPS = {OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY}
TIMELOCK_OPS = {OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY}
CONDITIONAL_OPS = {OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF}
HASH_OPS = {OP_SHA256, OP_HASH160, OP_HASH256, OP_RIPEMD160}

# Control-block shapes for Taproot script-path spends (handled in decode.py).


class ParsedScript:
    """Token stream plus derived structural facts for one revealed script."""

    def __init__(self, raw):
        self.raw = bytes(raw)
        self.items = []          # list of ('op', CScriptOp) | ('push', bytes)
        self.parse_error = None
        try:
            for opcode, data, _idx in CScript(self.raw).raw_iter():
                if data is None:
                    self.items.append(("op", opcode))
                else:
                    self.items.append(("push", bytes(data)))
        except (CScriptInvalidError, CScriptTruncatedPushDataError,
                ValueError) as exc:
            self.parse_error = str(exc)

    # -- element helpers ----------------------------------------------------

    def op_name(self, item):
        if item[0] == "op":
            return _op_name(item[1])
        return "<push %d>" % len(item[1])

    def is_op(self, idx, *ops):
        it = self.items[idx]
        return it[0] == "op" and it[1] in ops

    def is_small_int(self, idx):
        it = self.items[idx]
        return it[0] == "op" and OP_1 <= it[1] <= OP_16

    def is_push(self, idx):
        return self.items[idx][0] == "push"

    def push_data(self, idx):
        return self.items[idx][1]

    def small_int(self, idx):
        it = self.items[idx]
        if it[0] == "op" and OP_1 <= it[1] <= OP_16:
            return int(it[1]) - int(OP_1) + 1
        return None

    def decode_num_push(self, idx):
        """Decode a pushed script number (LE, sign bit in the top byte)."""
        data = self.push_data(idx)
        if not data:
            return 0
        neg = bool(data[-1] & 0x80)
        magnitude = bytearray(data)
        magnitude[-1] &= 0x7F
        value = int.from_bytes(bytes(magnitude), "little")
        return -value if neg else value

    # -- structural scans ---------------------------------------------------

    def script_len(self):
        return len(self.items)

    def multisigs(self):
        """All CHECKMULTISIG constructions: (k, n, key_positions, cm_pos).

        Returns a list so compound scripts (multiple quorums) are visible.
        """
        out = []
        n_items = len(self.items)
        for i, item in enumerate(self.items):
            if item[0] != "op" or item[1] not in MULTISIG_CHECK_OPS:
                continue
            if i < 1:
                continue
            n_idx = i - 1
            n = self.small_int(n_idx)
            if n is None or not (1 <= n <= 20):
                continue
            key_first = n_idx - n
            if key_first < 1:
                continue
            if not all(self.is_push(j) for j in range(key_first, n_idx)):
                continue
            k_idx = key_first - 1
            k = self.small_int(k_idx)
            if k is None or not (1 <= k <= n):
                continue
            out.append({
                "k": k,
                "n": n,
                "key_positions": list(range(key_first, n_idx)),
                "cm_pos": i,
                "k_idx": k_idx,
                "n_idx": n_idx,
            })
        return out

    def checksigadd_chain(self):
        """Recognize the BIP342-style threshold pattern:

            <pk1> OP_CHECKSIGADD <pk2> OP_CHECKSIGADD ... <pkN>
            OP_CHECKSIGADD <k> OP_GREATERTHANOREQUAL   (or GREATERTHAN /
            NUMEQUAL / NUMEQUALVERIFY / LESSTHAN family)
        """
        ops = [it[1] for it in self.items if it[0] == "op"]
        if OP_CHECKSIGADD not in ops:
            return None
        n_items = len(self.items)
        # Locate the trailing comparison after the last CHECKSIGADD.
        last_csa = max(i for i, it in enumerate(self.items)
                       if it[0] == "op" and it[1] == OP_CHECKSIGADD)
        if last_csa + 2 >= n_items:
            return None
        if not self.is_small_int(last_csa + 1):
            return None
        if not self.is_op(last_csa + 2, OP_GREATERTHANOREQUAL, OP_GREATERTHAN,
                          OP_NUMEQUAL, OP_NUMEQUALVERIFY,
                          OP_LESSTHANOREQUAL, OP_LESSTHAN):
            return None
        k = self.small_int(last_csa + 1)
        # Walk backwards collecting <pk> OP_CHECKSIGADD pairs.
        pos = last_csa
        keys = []
        while pos >= 1 and self.is_op(pos, OP_CHECKSIGADD) \
                and self.is_push(pos - 1):
            keys.append(pos - 1)
            pos -= 2
        keys.reverse()
        if not keys:
            return None
        return {
            "k": k,
            "n": len(keys),
            "key_positions": keys,
            "tail_pos": last_csa + 2,
        }

    def timelocks(self):
        """Timelock constraints: (op_name, value_or_None, position)."""
        out = []
        for i, item in enumerate(self.items):
            if item[0] == "op" and item[1] in TIMELOCK_OPS:
                value = None
                if i >= 1:
                    if self.is_small_int(i - 1):
                        value = self.small_int(i - 1)
                    elif self.is_push(i - 1):
                        try:
                            value = self.decode_num_push(i - 1)
                        except ValueError:
                            value = None
                name = ("CLTV" if item[1] == OP_CHECKLOCKTIMEVERIFY
                        else "CSV")
                out.append({"op": name, "value": value, "pos": i})
        return out

    def conditionals(self):
        counts = {"if": 0, "notif": 0, "else": 0, "endif": 0}
        for it in self.items:
            if it[0] != "op":
                continue
            if it[1] == OP_IF:
                counts["if"] += 1
            elif it[1] == OP_NOTIF:
                counts["notif"] += 1
            elif it[1] == OP_ELSE:
                counts["else"] += 1
            elif it[1] == OP_ENDIF:
                counts["endif"] += 1
        return counts

    def hashlocks(self):
        """(<hash-op>, <pushed digest>, position) triples."""
        out = []
        n = len(self.items)
        for i, item in enumerate(self.items):
            if item[0] == "op" and item[1] in HASH_OPS and i + 2 < n \
                    and self.is_push(i + 1) \
                    and self.is_op(i + 2, OP_EQUALVERIFY, OP_EQUAL):
                out.append({
                    "hash_op": str(item[1]),
                    "digest_hex": self.push_data(i + 1).hex(),
                    "pos": i,
                })
        return out

    def key_positions(self, tapscript=False):
        """Push positions holding pubkey-shaped data.

        33-byte 02/03-prefixed and 65-byte 04-prefixed pushes are keys.
        32-byte pushes count as x-only keys only in tapscripts and only
        when a signature-checking opcode is adjacent, because 32-byte
        pushes are otherwise indistinguishable from hash preimages.
        """
        positions = []
        n = len(self.items)
        for i, item in enumerate(self.items):
            if item[0] != "push":
                continue
            data = item[1]
            if len(data) == 33 and data[0] in (0x02, 0x03):
                positions.append(i)
            elif len(data) == 65 and data[0] == 0x04:
                positions.append(i)
            elif tapscript and len(data) == 32:
                adj_sig_op = (
                    (i + 1 < n and self.is_op(i + 1, OP_CHECKSIG,
                                              OP_CHECKSIGVERIFY,
                                              OP_CHECKSIGADD))
                    or (i >= 1 and self.is_op(i - 1, OP_CHECKSIGADD))
                )
                if adj_sig_op:
                    positions.append(i)
        return positions

    def has_sig_check(self):
        return any(it[0] == "op" and it[1] in SIG_CHECK_OPS | MULTISIG_CHECK_OPS
                   for it in self.items)


# -- key/signature shape helpers -------------------------------------------

def is_pubkey_data(data):
    return (len(data) == 33 and data[0] in (0x02, 0x03)) or \
           (len(data) == 65 and data[0] == 0x04)


def is_xonly_data(data):
    return len(data) == 32


def is_der_signature(data):
    """DER ECDSA signature with sighash-type suffix (or bare)."""
    if len(data) < 9 or len(data) > 73:
        return False
    if data[0] != 0x30:
        return False
    # data[1] covers the DER body; a sighash suffix adds one byte.
    if data[1] not in (len(data) - 3, len(data) - 2):
        return False
    return len(data) >= 5 and data[2] == 0x02


def split_sighash(data, schnorr=False):
    """Return (sig_bytes_without_suffix, sighash_type_int)."""
    if schnorr:
        if len(data) == 64:
            return data, 0x00  # SIGHASH_DEFAULT
        return data[:-1], data[-1]
    return data[:-1], data[-1]


# -- template construction ---------------------------------------------------

def _classify_push(parsed, idx, tapscript):
    """Return (l2_label, l3_label) for a push item in the templates."""
    data = parsed.push_data(idx)
    if is_pubkey_data(data):
        return "<PUBKEY>", "<P>"
    if tapscript and is_xonly_data(data) and idx in parsed.key_positions(True):
        return "<PUBKEY>", "<P>"
    if is_der_signature(data):
        return "<SIG>", "<S>"
    # Numeric feeds into a timelock check: L2 keeps the value, L3 drops it.
    n = len(parsed.items)
    if idx + 1 < n:
        nxt = parsed.items[idx + 1]
        if nxt[0] == "op" and nxt[1] in TIMELOCK_OPS:
            try:
                value = parsed.decode_num_push(idx)
                return "<NUM:%d>" % value, "<T>"
            except ValueError:
                pass
    return "<DATA%d>" % len(data), "<D>"


def build_templates(parsed, tapscript=False):
    """Return (template_l2, template_l3) strings.

    L2 keeps timelock VALUES and data-push lengths; L3 normalizes them.
    Thresholds and branch structure stay in both.
    """
    l2_parts = []
    l3_parts = []
    keypos = set(parsed.key_positions(tapscript))
    for i, (kind, val) in enumerate(parsed.items):
        if kind == "op":
            name = _op_name(val)
            l2_parts.append(name)
            l3_parts.append(name)
            continue
        if i in keypos:
            l2_parts.append("<PUBKEY>")
            l3_parts.append("<P>")
            continue
        if is_der_signature(val):
            l2_parts.append("<SIG>")
            l3_parts.append("<S>")
            continue
        l2_label, l3_label = _classify_push(parsed, i, tapscript)
        l2_parts.append(l2_label)
        l3_parts.append(l3_label)
    return " ".join(l2_parts), " ".join(l3_parts)


# -- family classification (L4) ----------------------------------------------

def classify_family(parsed, tapscript=False):
    """Rule-based wallet family. Generic by design: a family label is a
    structural bucket, never a provider attribution."""
    multisigs = parsed.multisigs()
    csa = parsed.checksigadd_chain()
    timelocks = parsed.timelocks()
    conds = parsed.conditionals()
    hashlocks = parsed.hashlocks()
    has_cond = (conds["if"] + conds["notif"]) > 0

    if tapscript:
        if csa and not has_cond and not timelocks:
            return "taproot_scriptpath_multisig"
        if csa and (has_cond or timelocks):
            return "taproot_scriptpath_conditional"
        if parsed.has_sig_check() and (has_cond or timelocks):
            return "taproot_conditional_recovery"
        if parsed.has_sig_check():
            return "taproot_scriptpath_other"
        return "taproot_unknown"

    if multisigs:
        families = []
        if timelocks:
            families.append("timelocked_recovery_multisig")
        if has_cond:
            families.append("conditional_multisig")
        if hashlocks:
            families.append("hashlock_multisig")
        if families:
            return "+".join(families)
        return "standard_multisig"

    if parsed.has_sig_check():
        if timelocks:
            return "timelocked_singlesig_recovery"
        if has_cond:
            return "conditional_policy"
        if hashlocks:
            return "hashlock_policy"
        return "sigscript_policy"
    if timelocks or has_cond or hashlocks:
        return "non_signature_policy"
    return "unknown"


def analyze_script(raw, tapscript=False):
    """Full analysis of one revealed script. Returns a dict matching the
    revealed_scripts table columns (minus observation bookkeeping)."""
    parsed = ParsedScript(raw)
    result = {
        "script_hex": raw.hex(),
        "script_sha256": hashlib.sha256(raw).hexdigest(),
        "parse_error": parsed.parse_error,
        "tapscript": tapscript,
    }

    if parsed.parse_error is not None:
        result.update({
            "script_class": "unparseable",
            "family_l4": "unknown",
            "template_l2": None,
            "template_l3": None,
            "threshold": None,
            "n_keys": None,
            "keys_sorted": None,
            "pubkeys": [],
        })
        return result

    template_l2, template_l3 = build_templates(parsed, tapscript)
    keypos = parsed.key_positions(tapscript)
    pubkeys = [parsed.push_data(i) for i in keypos]

    # Deterministic script-level classification.
    multisigs = parsed.multisigs()
    csa = parsed.checksigadd_chain()
    if multisigs and not csa and len(multisigs) == 1 and \
            len(keypos) == multisigs[0]["n"]:
        m = multisigs[0]
        threshold, n_keys = m["k"], m["n"]
        script_class = "multisig"
        key_data = [parsed.push_data(i) for i in m["key_positions"]]
        keys_sorted = key_data == sorted(key_data)
    elif csa and len(keypos) == csa["n"]:
        threshold, n_keys = csa["k"], csa["n"]
        script_class = "taproot_multisig" if tapscript else "csa_multisig"
        key_data = [parsed.push_data(i) for i in csa["key_positions"]]
        keys_sorted = key_data == sorted(key_data)
    elif multisigs or csa:
        threshold = None
        n_keys = len(keypos)
        script_class = "compound_multisig"
        keys_sorted = None
    else:
        threshold = None
        n_keys = len(keypos)
        script_class = "other"
        keys_sorted = None

    family = classify_family(parsed, tapscript)

    result.update({
        "script_class": script_class,
        "family_l4": family,
        "template_l2": template_l2,
        "template_l3": template_l3,
        "threshold": threshold,
        "n_keys": n_keys,
        "keys_sorted": keys_sorted,
        "pubkeys": pubkeys,
        "multisigs": multisigs,
        "csa": csa,
        "timelocks": parsed.timelocks(),
        "conditionals": parsed.conditionals(),
        "hashlocks": parsed.hashlocks(),
    })
    return result
