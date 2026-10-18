"""Configuration loading for the multisig fingerprinting tool.

Reads an INI-style config file (config.toml by convention, INI syntax
because Python 3.9 ships no TOML parser). Every limit is configurable;
the defaults in config.toml.example sit below Blockchair's documented
no-key limits.
"""

import configparser
import os

DEFAULTS = {
    "blockchair": {
        "api_key": "",
        "base_url": "https://api.blockchair.com",
        "points_per_day": "1000",
        "requests_per_minute": "20",
        "requests_per_second": "1",
        "cost_raw_block": "1",
        "cost_raw_transaction": "1",
        "cost_dashboard_block": "1",
        "cost_dashboard_transaction": "1",
        "cost_indexed_transactions": "5",
        "cost_indexed_outputs": "10",
        "cost_stats": "1",
        "cost_unknown": "10",
        "throttle_cooldown_seconds": "300",
        "max_throttles_per_run": "3",
    },
    "storage": {
        "data_dir": "data",
        "db_filename": "corpus.sqlite3",
    },
    "scan": {
        "sample_blocks": "180",
        "random_seed": "20261018",
    },
}


class Config:
    def __init__(self, path=None):
        parser = configparser.ConfigParser()
        if path is None:
            # Repo root = parent of the msfp package directory.
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(root, "config.toml")
        if os.path.exists(path):
            parser.read(path)

        def get(section, key):
            return parser.get(section, key, fallback=DEFAULTS[section][key])

        bc = "blockchair"
        self.api_key = get(bc, "api_key") or None
        self.base_url = get(bc, "base_url").rstrip("/")
        self.points_per_day = int(get(bc, "points_per_day"))
        self.requests_per_minute = int(get(bc, "requests_per_minute"))
        self.requests_per_second = int(get(bc, "requests_per_second"))
        self.costs = {
            "raw_block": int(get(bc, "cost_raw_block")),
            "raw_transaction": int(get(bc, "cost_raw_transaction")),
            "dashboard_block": int(get(bc, "cost_dashboard_block")),
            "dashboard_transaction": int(get(bc, "cost_dashboard_transaction")),
            "indexed_transactions": int(get(bc, "cost_indexed_transactions")),
            "indexed_outputs": int(get(bc, "cost_indexed_outputs")),
            "stats": int(get(bc, "cost_stats")),
            "unknown": int(get(bc, "cost_unknown")),
        }
        self.throttle_cooldown_seconds = int(get(bc, "throttle_cooldown_seconds"))
        self.max_throttles_per_run = int(get(bc, "max_throttles_per_run"))

        st = "storage"
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(root, get(st, "data_dir"))
        self.db_path = os.path.join(self.data_dir, get(st, "db_filename"))

        sc = "scan"
        self.sample_blocks = int(get(sc, "sample_blocks"))
        self.random_seed = int(get(sc, "random_seed"))
