"""Tests for the enrichment pass's pure helpers."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from msfp.enrich import (bucket_id, bucket_shape, classify_signature_item,
                         classify_witness, input_bin, output_bin,
                         sequence_class)


def test_signature_classification_der():
    # 72-byte DER signature with trailing sighash byte (0x01 = ALL).
    der = ("3044022009268045b1b70ed0b861b6184d3842f035fff60be6bf3933b58acc"
           "82be0b3bbc02202cfe2eb9d9c9c1c35ceeff431f1531b16385a580a366973"
           "8339be4791b9eb7ca01")
    kind, hashtype = classify_signature_item(bytes.fromhex(der))
    assert kind == "ecdsa"
    assert hashtype == 0x01


def test_signature_classification_schnorr():
    kind, hashtype = classify_signature_item(bytes(range(64)))
    assert kind == "schnorr"
    assert hashtype == 0x00
    item = bytes(range(64)) + b"\x03"
    kind, hashtype = classify_signature_item(item)
    assert kind == "schnorr"
    assert hashtype == 0x03


def test_signature_classification_rejects_non_signatures():
    assert classify_signature_item(b"") is None
    assert classify_signature_item(bytes(range(33))) is None  # pubkey
    assert classify_signature_item(b"\x50" + bytes(30)) is None  # annex
    assert classify_signature_item(bytes(64) + b"\xff") is None


def test_classify_witness_counts_both_schemes():
    der = ("3044022009268045b1b70ed0b861b6184d3842f035fff60be6bf3933b58acc"
           "82be0b3bbc02202cfe2eb9d9c9c1c35ceeff431f1531b16385a580a366973"
           "8339be4791b9eb7ca01")
    ecdsa, schnorr = classify_witness(["", der, der])
    assert (ecdsa, schnorr) == (2, 0)
    ecdsa, schnorr = classify_witness([bytes(range(64)).hex()])
    assert (ecdsa, schnorr) == (0, 1)


def test_sequence_classes():
    assert sequence_class(0xFFFFFFFF) == "final"
    assert sequence_class(0xFFFFFFFD) == "disabled"
    assert sequence_class(0xFFFFFFFE) == "disabled"
    assert sequence_class(0xFFFFFFFC) == "rbf_flagged"
    assert sequence_class(51840) == "timelock"


def test_size_bins():
    assert input_bin(1) == "1"
    assert input_bin(10) == "2-10"
    assert input_bin(50) == "11-50"
    assert input_bin(200) == ">50"
    assert output_bin(2) == "2"
    assert output_bin(4) == "3-5"
    assert output_bin(78) == ">5"


def test_bucket_identity_is_stable():
    shape = bucket_shape("p2wsh_witness", "OP_2 <P>", 2, 3, 0, [])
    assert bucket_id(shape) == bucket_id(bucket_shape(
        "p2wsh_witness", "OP_2 <P>", 2, 3, 0, []))
    other = bucket_id(bucket_shape("p2wsh_witness", "OP_2 <P>", 2, 3, 1, []))
    assert other != bucket_id(shape)
    with_tl = bucket_id(bucket_shape("p2wsh_witness", "T", None, 2, None,
                                     [51840]))
    assert "csv51840" in with_tl
