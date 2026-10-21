from __future__ import annotations

import os
import socket
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from conftest import privilege_drop_kwargs, wait_for_health
from schema_data import Rate

SERVER_BINARY = "/app/rpt7_server"

GENERATED_FILERS = 300000
GENERATED_OVERRIDE_FILERS = 75000
OVERRIDE_SLOTS = [("US", "S"), ("US", "D"), ("EU", "S"), ("EU", "D")]
_SLOT_CROSS_BORDER = [Rate(1, 2), Rate(1, 4), Rate(3, 4), Rate(1, 2)]
_SLOT_RETAIL = [Rate(3, 4), Rate(1, 2), Rate(7, 8), Rate(5, 8)]


def generated_filer_code(n: int) -> str:
    return f"IS{n:06d}"


def generated_filer_name(n: int) -> str:
    return f"Registered Filer {n}"


def generated_filer_is_exempt(n: int) -> bool:
    return n % 9 == 0


def generated_override(n: int, jurisdiction: str, txn_type: str) -> tuple[int, Rate, Rate]:
    slot = OVERRIDE_SLOTS.index((jurisdiction, txn_type))
    row = (n - 1) * 4 + slot
    return 5000000 + row, _SLOT_CROSS_BORDER[slot], _SLOT_RETAIL[slot]


def time_decodes(base_url: str, payloads: list[str]) -> float:
    parts = urlsplit(base_url)
    address = (parts.hostname, parts.port)
    start = time.monotonic()
    for payload in payloads:
        body = payload.encode("ascii")
        with socket.create_connection(address, timeout=30) as sock:
            sock.sendall(
                b"POST /decode HTTP/1.1\r\nHost: rpt7\r\nContent-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\n\r\n"
                + body
            )
            while sock.recv(8192):
                pass
    return time.monotonic() - start


def apply_rate(value: int, rate) -> int:
    product = value * rate.num
    quotient, remainder = divmod(product, rate.den)
    return quotient + (1 if 2 * remainder >= rate.den else 0)


def expected_decision(
    exempt_org: bool,
    threshold_cents: int,
    cross_border_rate,
    retail_rate,
    amount_cents: int,
    flags: int,
) -> dict[str, object]:
    exempt_flag = bool(flags & 0x01)
    retail_flag = bool((flags >> 1) & 0x01)
    cross_border_flag = bool((flags >> 2) & 0x01)
    manual_review_flag = bool((flags >> 3) & 0x01)

    effective_threshold = threshold_cents
    if retail_flag:
        effective_threshold = apply_rate(effective_threshold, retail_rate)
    if cross_border_flag:
        effective_threshold = apply_rate(effective_threshold, cross_border_rate)

    exempt = exempt_org or exempt_flag
    reportable = manual_review_flag or (not exempt and abs(amount_cents) >= effective_threshold)
    return {
        "exempt": exempt,
        "retail": retail_flag,
        "cross_border": cross_border_flag,
        "manual_review": manual_review_flag,
        "threshold_cents": effective_threshold,
        "reportable": reportable,
    }


def assert_matches_expected_decision(body: dict, expected: dict) -> None:
    for key, value in expected.items():
        assert body[key] == value, f"field {key!r}: expected {value!r}, got {body[key]!r}"


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


_TOPOLOGY_SCHEMA_DDL = """
CREATE TABLE issuers (
    issuer_code TEXT PRIMARY KEY,
    issuer_name TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    exempt_org INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE rule_thresholds (
    jurisdiction TEXT NOT NULL,
    txn_type TEXT NOT NULL,
    threshold_cents INTEGER NOT NULL,
    cross_border_rate_num INTEGER NOT NULL DEFAULT 1,
    cross_border_rate_den INTEGER NOT NULL DEFAULT 1,
    retail_rate_num INTEGER NOT NULL DEFAULT 1,
    retail_rate_den INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (jurisdiction, txn_type)
);
CREATE TABLE issuer_rule_overrides (
    issuer_code TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    txn_type TEXT NOT NULL,
    threshold_cents INTEGER NOT NULL,
    cross_border_rate_num INTEGER NOT NULL DEFAULT 1,
    cross_border_rate_den INTEGER NOT NULL DEFAULT 1,
    retail_rate_num INTEGER NOT NULL DEFAULT 1,
    retail_rate_den INTEGER NOT NULL DEFAULT 1,
    effective_from TEXT NOT NULL DEFAULT '00000000',
    PRIMARY KEY (issuer_code, jurisdiction, txn_type, effective_from)
);
"""

_OVERRIDE_INSERT_COLUMNS = (
    "INSERT INTO issuer_rule_overrides "
    "(issuer_code, jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
    "cross_border_rate_den, retail_rate_num, retail_rate_den) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_TOPOLOGY_SCHEMA_DDL)


def build_topology_a_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [
            ("ZETA", "Zeta Mutual Holdings", "ASSET_MANAGER", 0),
            ("QRST", "Quorum Sovereign Fund", "SOVEREIGN_FUND", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("CA", "S", 1750000, 13, 20, 3, 4),
            ("CA", "D", 4200000, 11, 20, 1, 2),
            ("JP", "T", 620000, 7, 10, 5, 8),
        ],
    )
    conn.executemany(
        _OVERRIDE_INSERT_COLUMNS,
        [("ZETA", "CA", "D", 900000, 2, 5, 7, 8)],
    )
    conn.commit()
    conn.close()


def build_topology_b_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [
            ("NOVA", "Nova Capital Partners", "BROKER_DEALER", 0),
            ("HALO", "Halo Sovereign Reserve", "CENTRAL_BANK", 1),
            ("ECHO", "Echo Clearing Cooperative", "CLEARINGHOUSE", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("US", "S", 2200000, 3, 10, 3, 4),
            ("EU", "D", 5000000, 21, 50, 5, 8),
            ("SG", "P", 725000, 3333, 10000, 1, 2),
            ("JP", "T", 1000003, 1, 4, 3, 4),
            ("CA", "S", 1000001, 1, 2, 1, 2),
            ("JP", "D", 3000000007, 499999999, 1000000000, 1, 2),
            ("CA", "D", 1000000066, 69, 100, 3, 4),
            ("CA", "P", 1000001, 3, 4, 2, 3),
        ],
    )
    conn.executemany(
        _OVERRIDE_INSERT_COLUMNS,
        [
            ("NOVA", "US", "S", 900000, 1, 5, 7, 8),
            ("NOVA", "EU", "D", 1800000, 33, 100, 5, 8),
            ("NOVA", "JP", "T", 600002, 3, 4, 1, 2),
            ("NOVA", "CA", "S", 800001, 1, 4, 7, 8),
        ],
    )
    conn.commit()
    conn.close()


def build_topology_c_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [
            ("QUOT", 'Acme "Premier" Holdings\\Group', "BROKER_DEALER", 0),
            ("lowj", "Lowercase Code Test Corp", "BROKER_DEALER", 0),
            ("NOOV", "No Override Test Corp", "BROKER_DEALER", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("US", "S", 1000000, 1, 2, 3, 4),
            ("eu", "d", 2000000, 1, 2, 1, 2),
        ],
    )
    conn.executemany(
        _OVERRIDE_INSERT_COLUMNS,
        [("lowj", "eu", "d", 3000000, 1, 4, 1, 2)],
    )
    conn.commit()
    conn.close()


TOPOLOGY_D_GENERIC = (1000000, Rate(1, 5), Rate(1, 2))
TOPOLOGY_D_OVERRIDE = (1000005, Rate(25, 100), Rate(5, 6))


def build_topology_d_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [("ZQNEG1", "Zenith Quorum Negotiants", "ASSET_MANAGER", 0)],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [("EU", "X", 1000000, 1, 5, 1, 2)],
    )
    conn.executemany(
        _OVERRIDE_INSERT_COLUMNS,
        [("ZQNEG1", "EU", "X", 1000005, 25, 100, 5, 6)],
    )
    conn.commit()
    conn.close()


TOPOLOGY_E_QUOTED_NAME = 'Quo"Vadis\\Trading LLC'


def build_topology_e_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [
            ("zqjson1", TOPOLOGY_E_QUOTED_NAME, "BROKER_DEALER", 0),
            ("zqjson2", "Decoy Corp", "BROKER_DEALER", 0),
            ("ZQCTRL", "Line1\nLine2 Corp", "BROKER_DEALER", 0),
            ("ZQTAB", "Column1\tColumn2 Corp", "BROKER_DEALER", 0),
            ("ZQUNI", "Société Générale Ñoño 日本 Corp", "BROKER_DEALER", 0),
            ("lowov", "Lowercase Override Reader Corp", "BROKER_DEALER", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [("eu", "w", 1000000, 1, 2, 1, 2), ("us", "w", 2000000, 1, 2, 1, 2)],
    )
    conn.executemany(
        _OVERRIDE_INSERT_COLUMNS,
        [
            ("zqjson1", "eu", "w", 500000, 1, 2, 1, 2),
            ("zqjson2", "eu", "w", 999000000, 1, 2, 1, 2),
            ("lowov", "us", "w", 700000, 1, 2, 1, 2),
        ],
    )
    conn.commit()
    conn.close()


QURO_US_D_VERSIONS = [
    ("20250101", 900000, Rate(1, 4), Rate(3, 8)),
    ("20260301", 950001, Rate(11, 20), Rate(7, 16)),
    ("20260901", 1000000, Rate(3, 8), Rate(9, 16)),
]

DEEP_FILER_AMENDMENT_ISSUER = "IS050000"
DEEP_FILER_ORIGINAL = (5199996, Rate(1, 2), Rate(3, 4))
DEEP_FILER_AMENDMENT_VERSIONS = [
    ("00000000", 5199996, Rate(1, 2), Rate(3, 4)),
    ("20260601", 5500000, Rate(3, 5), Rate(2, 3)),
]


def resolve_temporal_override(versions: list[tuple], filing_date8: str) -> tuple | None:
    eligible = [v for v in versions if v[0] <= filing_date8]
    if not eligible:
        return None
    return max(eligible, key=lambda v: v[0])[1:]


def build_topology_f_database(path: Path) -> None:
    conn = sqlite3.connect(path)
    _create_schema(conn)
    conn.executemany(
        "INSERT INTO issuers VALUES (?, ?, ?, ?)",
        [
            ("RAFT", "Raft Clearing Partners", "CLEARINGHOUSE", 0),
            ("NOKO", "Noko Reserve Bank", "CENTRAL_BANK", 0),
            ("zqmix", "Lowercase Temporal Test Corp", "CLEARINGHOUSE", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO rule_thresholds VALUES (?, ?, ?, ?, ?, ?, ?)",
        [("CA", "W", 2000000, 1, 2, 3, 4), ("mx", "z", 800000, 1, 2, 1, 2)],
    )
    conn.executemany(
        "INSERT INTO issuer_rule_overrides "
        "(issuer_code, jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den, effective_from) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("zqmix", "mx", "z", 300000, 1, 3, 2, 5, "20240101"),
            ("zqmix", "mx", "z", 350000, 3, 7, 4, 9, "20250601"),
        ],
    )
    conn.executemany(
        "INSERT INTO issuer_rule_overrides "
        "(issuer_code, jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den, effective_from) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("RAFT", "CA", "W", 500000, 1, 3, 2, 3, "20240601"),
            ("RAFT", "CA", "W", 620000, 5, 9, 7, 12, "20250901"),
        ],
    )
    conn.commit()
    conn.close()


RAFT_CA_W_VERSIONS = [
    ("20240601", 500000, Rate(1, 3), Rate(2, 3)),
    ("20250901", 620000, Rate(5, 9), Rate(7, 12)),
]
RAFT_CA_W_GENERIC = (2000000, Rate(1, 2), Rate(3, 4))

ZQMIX_MX_Z_VERSIONS = [
    ("20240101", 300000, Rate(1, 3), Rate(2, 5)),
    ("20250601", 350000, Rate(3, 7), Rate(4, 9)),
]
ZQMIX_MX_Z_GENERIC = (800000, Rate(1, 2), Rate(1, 2))


@dataclass
class AlternateServer:
    base_url: str
    startup_error: str | None


def launch_alternate_server(
    db_path: Path, timeout_sec: float = 15.0
) -> tuple[subprocess.Popen | None, AlternateServer]:
    port = _free_tcp_port()
    for ancestor in (db_path.parent, db_path.parent.parent, db_path.parent.parent.parent):
        os.chmod(ancestor, 0o755)
    os.chmod(db_path, 0o644)
    env = dict(os.environ, RPT7_DB_PATH=str(db_path), RPT7_PORT=str(port))
    base_url = f"http://127.0.0.1:{port}"

    process = None
    startup_error = None
    try:
        process = subprocess.Popen([SERVER_BINARY], env=env, **privilege_drop_kwargs())
    except OSError as exc:
        startup_error = f"could not launch {SERVER_BINARY}: {exc}"
    else:
        startup_error = wait_for_health(base_url, timeout_sec)

    return process, AlternateServer(base_url=base_url, startup_error=startup_error)
