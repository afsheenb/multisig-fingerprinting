"""SQLite schema and connection management for the corpus database.

One database file holds the corpus, the API request ledger, and
acquisition checkpoints so that every process restart resumes from
persisted state. The ledger is the authoritative record of points
consumed; the daily budget is computed from it, never from memory.
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    block_time TEXT NOT NULL,
    n_tx INTEGER NOT NULL,
    fetched_utc TEXT,
    cache_path TEXT,
    raw_bytes INTEGER,
    request_cost REAL
);

CREATE TABLE IF NOT EXISTS txs (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL REFERENCES blocks(height),
    version INTEGER,
    locktime INTEGER,
    n_inputs INTEGER,
    n_outputs INTEGER,
    block_time TEXT
);

CREATE TABLE IF NOT EXISTS inputs (
    input_id INTEGER PRIMARY KEY AUTOINCREMENT,
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    block_time TEXT,
    prevout_txid TEXT,
    prevout_n INTEGER,
    prevout_value INTEGER,
    prevout_spk_hex TEXT,
    sequence INTEGER,
    script_sig_hex TEXT,
    witness_json TEXT,
    input_form TEXT,
    UNIQUE(txid, input_index)
);
CREATE INDEX IF NOT EXISTS idx_inputs_form ON inputs(input_form);
CREATE INDEX IF NOT EXISTS idx_inputs_prevout ON inputs(prevout_txid, prevout_n);

CREATE TABLE IF NOT EXISTS revealed_scripts (
    script_sha256 TEXT PRIMARY KEY,
    script_hex TEXT NOT NULL,
    source TEXT NOT NULL,              -- p2sh_redeem | p2wsh_witness | p2sh_p2wsh_witness | taproot_leaf
    script_class TEXT,                 -- classifier output: multisig, miniscript, taproot_multisig, unknown, ...
    family_l4 TEXT,
    template_l2 TEXT,
    template_l3 TEXT,
    threshold INTEGER,
    n_keys INTEGER,
    keys_sorted INTEGER,               -- 1 sorted (BIP67), 0 unsorted, NULL not applicable
    first_seen_height INTEGER,
    last_seen_height INTEGER,
    n_observations INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS script_keys (
    script_sha256 TEXT NOT NULL REFERENCES revealed_scripts(script_sha256),
    pubkey_hex TEXT NOT NULL,
    position INTEGER,
    PRIMARY KEY (script_sha256, pubkey_hex, position)
);
CREATE INDEX IF NOT EXISTS idx_script_keys_pubkey ON script_keys(pubkey_hex);

CREATE TABLE IF NOT EXISTS script_observations (
    input_id INTEGER PRIMARY KEY REFERENCES inputs(input_id),
    script_sha256 TEXT REFERENCES revealed_scripts(script_sha256),
    n_signatures INTEGER,
    sighash_types TEXT,
    executed_branch TEXT
);

CREATE TABLE IF NOT EXISTS api_ledger (
    ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    params TEXT,
    http_status INTEGER,
    estimated_cost REAL,
    actual_cost REAL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS mempool_ledger (
    ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    http_status INTEGER,
    note TEXT
);

CREATE TABLE IF NOT EXISTS validation_results (
    input_id INTEGER PRIMARY KEY REFERENCES inputs(input_id),
    commitment_status TEXT NOT NULL,   -- ok | failed | not_verifiable | not_applicable
    signatures_present INTEGER,
    signatures_verified INTEGER,
    verified_key_positions_json TEXT,
    verified_via TEXT NOT NULL         -- ecdsa_bip143 | taproot_key | taproot_script
);

CREATE TABLE IF NOT EXISTS plan (
    height INTEGER PRIMARY KEY,
    strategy TEXT NOT NULL,            -- random | regular | manual
    done INTEGER DEFAULT 0
);
"""


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    return conn


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )
    conn.commit()
