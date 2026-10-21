from __future__ import annotations

import itertools
import json
import os
import sqlite3
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import conftest
import held_out_data
import pytest
import requests
import schema_data
from conftest import privilege_drop_kwargs
from held_out_data import (
    DEEP_FILER_AMENDMENT_ISSUER,
    OVERRIDE_SLOTS,
    QURO_US_D_VERSIONS,
    RAFT_CA_W_GENERIC,
    RAFT_CA_W_VERSIONS,
    TOPOLOGY_D_OVERRIDE,
    TOPOLOGY_E_QUOTED_NAME,
    ZQMIX_MX_Z_GENERIC,
    ZQMIX_MX_Z_VERSIONS,
    apply_rate,
    assert_matches_expected_decision,
    build_topology_a_database,
    build_topology_b_database,
    build_topology_c_database,
    build_topology_d_database,
    build_topology_e_database,
    build_topology_f_database,
    expected_decision,
    generated_filer_code,
    generated_filer_is_exempt,
    generated_filer_name,
    generated_override,
    launch_alternate_server,
    resolve_temporal_override,
)

HOST = os.environ.get("RPT7_HOST", "127.0.0.1")
PORT = 8080  # instruction.md's documented default; see conftest.rpt7_server
BASE_URL = f"http://{HOST}:{PORT}"
SCHEMA_PATH = os.environ.get("RPT7_SCHEMA_PATH", schema_data.DEFAULT_SCHEMA_PATH)
SERVER_BINARY = "/app/rpt7_server"
DB_PATH = "/app/data/rpt7.db"

ALLOWED_SHARED_LIBRARIES = frozenset(
    {"libc", "libm", "libpthread", "libdl", "librt", "libsqlite3"}
)


def _elf_needed_libraries(path: str) -> list[str]:
    data = Path(path).read_bytes()
    assert data[:4] == b"\x7fELF", f"{path} is not an ELF binary"
    assert data[4] == 2, f"{path} is not a 64-bit ELF binary"
    endian = "<" if data[5] == 1 else ">"

    (e_shoff,) = struct.unpack_from(endian + "Q", data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 0x3A)

    needed: list[str] = []
    for index in range(e_shnum):
        header = e_shoff + index * e_shentsize
        (sh_type,) = struct.unpack_from(endian + "I", data, header + 0x04)
        if sh_type != 6:  # SHT_DYNAMIC
            continue
        sh_offset, sh_size = struct.unpack_from(endian + "QQ", data, header + 0x18)
        (sh_link,) = struct.unpack_from(endian + "I", data, header + 0x28)
        (strtab_offset,) = struct.unpack_from(
            endian + "Q", data, e_shoff + sh_link * e_shentsize + 0x18
        )
        for entry in range(sh_offset, sh_offset + sh_size, 16):
            tag, value = struct.unpack_from(endian + "qQ", data, entry)
            if tag == 0:  # DT_NULL
                break
            if tag == 1:  # DT_NEEDED
                start = strtab_offset + value
                needed.append(data[start : data.index(b"\0", start)].decode())
    return needed


SCHEMA = schema_data.load(SCHEMA_PATH)

ALL_RULE_ROWS = [
    ("US", "S"), ("US", "P"), ("US", "T"), ("US", "D"),
    ("EU", "S"), ("EU", "P"), ("EU", "T"), ("EU", "D"),
    ("UK", "S"), ("UK", "P"), ("UK", "T"), ("UK", "D"),
    ("SG", "S"), ("SG", "P"), ("SG", "T"), ("SG", "D"),
    ("JP", "S"), ("JP", "P"), ("JP", "D"),
]
NON_EXACT_RATE_ROWS = [
    ("US", "T"), ("EU", "S"), ("EU", "P"), ("EU", "D"), ("UK", "D"), ("JP", "P"), ("JP", "D"),
]


def coerce_fragment_value(json_value: str) -> bool | int | str:
    if json_value in ("true", "false"):
        return json_value == "true"
    stripped = json_value.removeprefix("-")
    if stripped.isdigit():
        return int(json_value)
    return json_value


@dataclass(frozen=True)
class Filing:
    issuer_code: str
    jurisdiction: str
    txn_type: str
    amount_cents: int
    date8: str
    flags: int

    def checksum(self) -> int:
        canon = (
            f"{self.issuer_code},{self.jurisdiction},{self.txn_type},"
            f"{self.amount_cents},{self.date8},{self.flags:02x}"
        )
        return sum(canon.encode("ascii")) % 97

    def canonical_payload(self) -> str:
        return (
            f"RPT7,{self.issuer_code},{self.jurisdiction},{self.txn_type},"
            f"{self.amount_cents},{self.date8},{self.flags:02x},{self.checksum():02d}"
        )

    def noisy_payload(self, variant: int) -> str:
        check = self.checksum()

        if variant % 4 == 0:
            amount_text = str(self.amount_cents)
        elif variant % 4 == 1:
            amount_text = f"+{self.amount_cents}"
        elif variant % 4 == 2:
            amount_text = f"0000{self.amount_cents}"
        elif self.amount_cents < 0:
            amount_text = f"({-self.amount_cents})"
        else:
            amount_text = str(self.amount_cents)

        if variant % 3 == 0:
            date_text = self.date8
        elif variant % 3 == 1:
            date_text = f"{self.date8[0:4]}-{self.date8[4:6]}-{self.date8[6:8]}"
        else:
            date_text = f"{self.date8[0:4]}/{self.date8[4:6]}/{self.date8[6:8]}"

        noisy = variant % 2 != 0
        magic = "rpt7" if noisy else "RPT7"
        issuer = self.issuer_code.lower() if noisy else self.issuer_code
        jurisdiction = self.jurisdiction.lower() if noisy else self.jurisdiction
        txn_type = self.txn_type.lower() if noisy else self.txn_type
        flags_text = f"{self.flags:02x}"
        check_text = f"0{check}" if variant % 6 == 0 else str(check)

        pad = "  " if variant % 5 == 0 else ""
        fields = [magic, issuer, jurisdiction, txn_type, amount_text, date_text, flags_text, check_text]
        return ",".join(f"{pad}{field}{pad}" for field in fields)

    def with_field_padding(self, field_index: int, leading: bool, trailing: bool) -> str:
        parts = [
            "RPT7",
            self.issuer_code,
            self.jurisdiction,
            self.txn_type,
            str(self.amount_cents),
            self.date8,
            f"{self.flags:02x}",
            f"{self.checksum():02d}",
        ]
        pad_left = "  " if leading else ""
        pad_right = "  " if trailing else ""
        parts[field_index] = f"{pad_left}{parts[field_index]}{pad_right}"
        return ",".join(parts)

    def with_mutated_field(self, field_index: int) -> str:
        parts = [
            "RPT7",
            self.issuer_code,
            self.jurisdiction,
            self.txn_type,
            str(self.amount_cents),
            self.date8,
            f"{self.flags:02x}",
            f"{self.checksum():02d}",
        ]
        if field_index == 1:
            parts[1] = parts[1] + "X"
        elif field_index == 2:
            parts[2] = "ZZ" if parts[2] != "ZZ" else "YY"
        elif field_index == 3:
            parts[3] = "P" if parts[3] != "P" else "S"
        elif field_index == 4:
            parts[4] = str(self.amount_cents + 1)
        elif field_index == 5:
            digits = list(self.date8)
            digits[-1] = "1" if digits[-1] != "1" else "2"
            parts[5] = "".join(digits)
        elif field_index == 6:
            parts[6] = f"{(self.flags ^ 0x0F):02x}"
        return ",".join(parts)


def decode(payload: str, base_url: str = BASE_URL) -> requests.Response:
    return requests.post(f"{base_url}/decode", data=payload, timeout=5.0)


def assert_decodes_to(payload: str, base_url: str = BASE_URL, **expected_fields) -> dict:
    response = decode(payload, base_url=base_url)
    assert response.status_code == 200
    body = response.json()
    for field, value in expected_fields.items():
        assert body[field] == value
    return body


def test_server_binary_starts_and_serves_health():
    """Server binary starts and serves health."""
    assert conftest.startup_error is None, conftest.startup_error


def test_bad_checksum_is_rejected():
    """Tampered checksum digit is rejected."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    payload = filing.canonical_payload()
    last_digit = int(payload[-1])
    tampered = payload[:-1] + str((last_digit + 1) % 10)
    response = decode(tampered)
    assert response.status_code == 400
    assert response.json()["error"] == "checksum_mismatch"


def test_binary_links_only_against_libc_and_sqlite():
    """Binary links only libc and sqlite."""
    needed = _elf_needed_libraries(SERVER_BINARY)
    unexpected = sorted(
        lib for lib in needed if lib.split(".so")[0] not in ALLOWED_SHARED_LIBRARIES
    )
    assert not unexpected, f"unexpected shared library dependencies: {unexpected} (all: {needed})"


@pytest.mark.parametrize("filer", [1, 37501, 75000, 75001, 112500, 150000, 187500, 299999, 300000])
def test_filers_across_the_whole_registry_resolve(filer):
    """Registry filers resolve name and exemption."""
    filing = Filing(generated_filer_code(filer), "UK", "T", 600000, "20260601", 0x00)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200, f"filer {filer} did not resolve: {response.text}"
    body = response.json()
    assert body["issuer_name"] == generated_filer_name(filer)
    assert body["exempt"] is generated_filer_is_exempt(filer)


@pytest.mark.parametrize("filer", [1, 37500, 50001, 74999])
@pytest.mark.parametrize(("jurisdiction", "txn_type"), [("US", "S"), ("US", "D"), ("EU", "S"), ("EU", "D")])
def test_override_rows_are_keyed_on_issuer_jurisdiction_and_type_together(
    filer, jurisdiction, txn_type
):
    """Override rows key on full composite."""
    threshold, _cross, _retail = generated_override(filer, jurisdiction, txn_type)
    filing = Filing(generated_filer_code(filer), jurisdiction, txn_type, threshold, "20260601", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        threshold_cents=threshold,
        reportable=not generated_filer_is_exempt(filer),
    )


@pytest.mark.parametrize("filer", [1, 37500, 74999])
def test_override_slots_for_one_filer_are_pairwise_distinct(filer):
    """Filer's four override thresholds are distinct."""
    values = [generated_override(filer, jurisdiction, txn_type)[0] for jurisdiction, txn_type in OVERRIDE_SLOTS]
    assert len(set(values)) == len(OVERRIDE_SLOTS)


@pytest.mark.parametrize("filer", [75001, 150000, 300000])
def test_filer_holding_no_override_falls_through_to_the_generic_rule(filer):
    """No-override filer falls to generic rule."""
    rule = SCHEMA.rule("US", "S")
    filing = Filing(generated_filer_code(filer), "US", "S", rule.threshold_cents, "20260601", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        threshold_cents=rule.threshold_cents,
        reportable=not generated_filer_is_exempt(filer),
    )


@pytest.mark.parametrize("filer", [1, 9, 74999, 75000, 75001, 299991, 300000])
def test_registry_boundary_filers_resolve_name_and_exemption_exactly(filer):
    """Registry-edge filers resolve name and exemption."""
    filing = Filing(generated_filer_code(filer), "UK", "T", 1, "20260601", 0x08)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200, f"filer {filer} did not resolve: {response.text}"
    body = response.json()
    assert body["issuer_name"] == generated_filer_name(filer)
    assert body["exempt"] is generated_filer_is_exempt(filer)
    assert body["reportable"] is True


def _database_snapshot(db_path) -> tuple[list, dict]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        schema = sorted(
            conn.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )
        contents = {}
        for obj_type, name, _sql in schema:
            if obj_type != "table":
                continue
            columns = tuple(row[1] for row in conn.execute(f'PRAGMA table_info("{name}")'))
            rows = sorted(repr(row) for row in conn.execute(f'SELECT * FROM "{name}"'))
            contents[name] = (columns, rows)
    finally:
        conn.close()
    return schema, contents


def test_reference_database_is_left_completely_unchanged(tmp_path):
    """Reference database is left completely unchanged."""
    reference = tmp_path / "reference.db"
    conn = sqlite3.connect(reference)
    conn.executescript(Path(SCHEMA_PATH).read_text())
    conn.commit()
    conn.close()

    expected_schema, expected_contents = _database_snapshot(reference)
    actual_schema, actual_contents = _database_snapshot(DB_PATH)

    assert actual_schema == expected_schema, "the database schema was altered"
    assert set(actual_contents) == set(expected_contents), "tables were added or removed"
    for name in expected_contents:
        assert actual_contents[name] == expected_contents[name], f"table {name!r} was modified"


REJECTED_PAYLOADS = [
    "RPT7,ACME,US,S,not-a-number,20260115,00,00",
    "RPT7,ACME,US,S,999999,20260115,00,abc",
]


@pytest.mark.parametrize("payload", REJECTED_PAYLOADS)
def test_rejected_payloads_carry_a_machine_readable_error_string(payload):
    """Rejected payloads carry machine-readable error string."""
    response = decode(payload)
    assert response.status_code == 400
    body = response.json()
    assert isinstance(body.get("error"), str) and body["error"], body


def test_bad_magic_produces_the_exact_documented_error_code():
    """Wrong magic string yields bad_magic."""
    response = decode("RPT7X,ACME,US,S,999999,20260115,00,00")
    assert response.status_code == 400
    assert response.json()["error"] == "bad_magic"


def test_empty_issuer_code_is_a_malformed_payload():
    """Empty issuer_code yields malformed_payload."""
    response = decode("RPT7,,US,S,999999,20260115,00,00")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_bad_date_format_is_a_malformed_payload():
    """Wrong-length date yields malformed_payload."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    checksum = filing.checksum()
    response = decode(f"RPT7,ACME,US,S,999999,2026011,00,{checksum:02d}")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_non_hex_flags_is_a_malformed_payload():
    """Non-hex flags field yields malformed_payload."""
    response = decode("RPT7,ACME,US,S,999999,20260115,ZZ,00")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_out_of_range_flags_is_a_malformed_payload():
    """Flags above 0x0F yields malformed_payload."""
    response = decode("RPT7,ACME,US,S,999999,20260115,1F,00")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_single_character_txn_type_violation_is_a_malformed_payload():
    """Multi-character txn_type yields malformed_payload."""
    response = decode("RPT7,ACME,US,SS,999999,20260115,00,00")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_checksum_out_of_numeric_range_is_a_malformed_payload():
    """Checksum above 96 yields malformed_payload."""
    response = decode("RPT7,ACME,US,S,999999,20260115,00,99")
    assert response.status_code == 400
    assert response.json()["error"] == "malformed_payload"


def test_unknown_issuer_produces_the_exact_documented_error_code():
    """Unregistered issuer yields unknown_issuer."""
    filing = Filing("ZZZZZ", "US", "S", 999999, "20260115", 0x00)
    response = decode(filing.canonical_payload())
    assert response.status_code == 400
    assert response.json()["error"] == "unknown_issuer"


def test_unknown_jurisdiction_produces_the_exact_documented_error_code():
    """Unregistered jurisdiction yields unknown_jurisdiction_or_type."""
    filing = Filing("ACME", "ZZ", "Q", 999999, "20260115", 0x00)
    response = decode(filing.canonical_payload())
    assert response.status_code == 400
    assert response.json()["error"] == "unknown_jurisdiction_or_type"


def test_unknown_path_returns_not_found():
    """Unknown path yields not_found."""
    response = requests.get(f"{BASE_URL}/nonexistent", timeout=5.0)
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_wrong_method_on_decode_returns_not_found():
    """GET on /decode yields not_found."""
    response = requests.get(f"{BASE_URL}/decode", timeout=5.0)
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_error_response_body_has_no_fields_beyond_error():
    """400 body carries only error key."""
    response = decode("RPT7,ACME,US,S,999999,20260115,00,00")
    assert response.status_code == 400
    assert set(response.json().keys()) == {"error"}


def test_error_response_content_type_is_json():
    """400 error response declares JSON type."""
    response = decode("RPT7,ACME,US,S,999999,20260115,00,00")
    assert response.status_code == 400
    assert "application/json" in response.headers.get("Content-Type", "")


def test_success_response_content_type_is_json():
    """200 success response declares JSON type."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200
    assert "application/json" in response.headers.get("Content-Type", "")


def test_post_to_health_endpoint_returns_not_found():
    """POST to /health yields not_found."""
    response = requests.post(f"{BASE_URL}/health", timeout=5.0)
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


@pytest.mark.parametrize("variant", [10, 30])
def test_formatting_noise_does_not_change_the_decision(variant):
    """Formatting noise never changes decoded outcome."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    canonical = decode(filing.canonical_payload())
    noisy = decode(filing.noisy_payload(variant))

    assert canonical.status_code == 200
    assert noisy.status_code == 200, f"variant {variant} should still decode: {filing.noisy_payload(variant)}"
    canonical_body = canonical.json()
    noisy_body = noisy.json()
    assert canonical_body["reportable"] == noisy_body["reportable"]
    assert canonical_body["amount_cents"] == noisy_body["amount_cents"]
    assert canonical_body["filing_date"] == noisy_body["filing_date"]
    assert canonical_body["issuer_code"] == noisy_body["issuer_code"]
    assert canonical_body["jurisdiction"] == noisy_body["jurisdiction"] == filing.jurisdiction
    assert canonical_body["txn_type"] == noisy_body["txn_type"] == filing.txn_type


FIELD_NAMES_BY_INDEX = {
    1: "issuer_code",
    2: "jurisdiction",
    3: "txn_type",
    4: "amount_cents",
    5: "filing_date",
    6: "flags",
    7: "checksum",
}


@pytest.mark.parametrize(
    ("field_index", "side"),
    [(1, "leading"), (7, "trailing")],
    ids=["issuer_code-leading", "checksum-trailing"],
)
def test_whitespace_on_a_single_side_of_a_field_is_still_trimmed(field_index, side):
    """Whitespace on either side is trimmed."""
    filing = Filing("ACME", "US", "S", 2000000, "20260115", 0x00)
    payload = filing.with_field_padding(
        field_index, leading=(side == "leading"), trailing=(side == "trailing")
    )
    response = decode(payload)
    assert response.status_code == 200, f"{FIELD_NAMES_BY_INDEX[field_index]} ({side}): {payload}"
    body = response.json()
    assert body["issuer_code"] == "ACME"
    assert body["reportable"] is True


@pytest.mark.parametrize(("jurisdiction", "txn_type"), ALL_RULE_ROWS)
def test_amount_exactly_at_threshold_is_reportable_for_every_rule(jurisdiction, txn_type):
    """Amount at threshold is reportable everywhere."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    filing = Filing("ACME", jurisdiction, txn_type, rule.threshold_cents, "20260115", 0x00)
    assert_decodes_to(filing.canonical_payload(), reportable=True)


@pytest.mark.parametrize(("jurisdiction", "txn_type"), ALL_RULE_ROWS)
def test_amount_one_cent_under_threshold_is_not_reportable_for_every_rule(jurisdiction, txn_type):
    """Amount under threshold is never reportable."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    filing = Filing("ACME", jurisdiction, txn_type, rule.threshold_cents - 1, "20260115", 0x00)
    assert_decodes_to(filing.canonical_payload(), reportable=False)


@pytest.mark.parametrize("jurisdiction", ["US", "SG"])
def test_cross_border_flag_scales_the_effective_threshold(jurisdiction):
    """Cross-border flag scales effective threshold."""
    rule = SCHEMA.rule(jurisdiction, "T")
    scaled_threshold = apply_rate(rule.threshold_cents, rule.cross_border_rate)

    below = Filing("ACME", jurisdiction, "T", scaled_threshold - 1, "20260115", 0x04)
    at = Filing("ACME", jurisdiction, "T", scaled_threshold, "20260115", 0x04)

    below_response = decode(below.canonical_payload())
    at_response = decode(at.canonical_payload())

    assert below_response.status_code == 200
    assert at_response.status_code == 200
    assert not below_response.json()["reportable"]
    assert at_response.json()["reportable"]


@pytest.mark.parametrize(("jurisdiction", "txn_type"), [("US", "S")])
def test_retail_flag_scales_the_effective_threshold(jurisdiction, txn_type):
    """Retail flag scales effective threshold."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    scaled = apply_rate(rule.threshold_cents, rule.retail_rate)
    assert scaled != rule.threshold_cents, "fixture assumption: the retail multiplier must bite"

    below = decode(Filing("ACME", jurisdiction, txn_type, scaled - 1, "20260115", 0x02).canonical_payload())
    at = decode(Filing("ACME", jurisdiction, txn_type, scaled, "20260115", 0x02).canonical_payload())

    assert below.status_code == 200
    assert at.status_code == 200
    assert below.json()["threshold_cents"] == scaled
    assert below.json()["reportable"] is False
    assert at.json()["reportable"] is True


@pytest.mark.parametrize(("amount_cents", "expected_reportable"), [(375000, False), (375001, True)])
def test_retail_and_cross_border_scalings_are_applied_in_sequence(amount_cents, expected_reportable):
    """Retail and cross-border scale sequentially."""
    rule = SCHEMA.rule("JP", "S")
    stepwise = apply_rate(
        apply_rate(rule.threshold_cents, rule.retail_rate), rule.cross_border_rate
    )
    combined = apply_rate(
        rule.threshold_cents,
        schema_data.Rate(
            rule.retail_rate.num * rule.cross_border_rate.num,
            rule.retail_rate.den * rule.cross_border_rate.den,
        ),
    )
    assert stepwise != combined, "fixture assumption: the two ways of composing must differ"

    assert_decodes_to(
        Filing("ACME", "JP", "S", amount_cents, "20260115", 0x06).canonical_payload(),
        threshold_cents=stepwise,
        reportable=expected_reportable,
    )


@pytest.mark.parametrize(("amount_cents", "expected_reportable"), [(499999, False), (500000, True)])
def test_the_two_adjustments_compose_in_the_filed_order(amount_cents, expected_reportable):
    """Adjustments compose in the filed order."""
    rule = SCHEMA.rule("JP", "P")
    retail_first = apply_rate(apply_rate(rule.threshold_cents, rule.retail_rate), rule.cross_border_rate)
    cross_first = apply_rate(apply_rate(rule.threshold_cents, rule.cross_border_rate), rule.retail_rate)
    assert retail_first != cross_first, "fixture assumption: the two orders must differ"

    assert_decodes_to(
        Filing("ACME", "JP", "P", amount_cents, "20261101", 0x06).canonical_payload(),
        threshold_cents=retail_first,
        reportable=expected_reportable,
    )


def test_issuer_override_supplies_its_own_retail_multiplier():
    """Override supplies its own retail rate."""
    override = SCHEMA.override("TORQ", "US", "D")
    generic = SCHEMA.rule("US", "D")
    override_scaled = apply_rate(override.threshold_cents, override.retail_rate)
    generic_scaled = apply_rate(override.threshold_cents, generic.retail_rate)
    assert override_scaled != generic_scaled, "fixture assumption: the two multipliers must differ"

    assert_decodes_to(
        Filing("TORQ", "US", "D", override_scaled, "20260115", 0x02).canonical_payload(),
        threshold_cents=override_scaled,
        reportable=True,
    )


def test_negative_amount_uses_absolute_value_for_threshold():
    """Negative amount uses absolute value."""
    rule = SCHEMA.rule("US", "S")
    filing = Filing("ACME", "US", "S", -rule.threshold_cents, "20260115", 0x00)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["reportable"]
    assert body["amount_cents"] == -rule.threshold_cents


@pytest.mark.parametrize(("jurisdiction", "txn_type"), [("US", "S")])
def test_parenthesized_negative_amount_matches_minus_sign_notation(jurisdiction, txn_type):
    """Parenthesized amount matches minus sign."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    minus_sign = Filing("ACME", jurisdiction, txn_type, -rule.threshold_cents, "20260115", 0x00)
    minus_response = decode(minus_sign.canonical_payload())

    checksum = minus_sign.checksum()
    parens_payload = (
        f"RPT7,ACME,{jurisdiction},{txn_type},({rule.threshold_cents}),20260115,00,{checksum:02d}"
    )
    parens_response = decode(parens_payload)

    assert minus_response.status_code == 200
    assert parens_response.status_code == 200, parens_payload
    assert minus_response.json()["amount_cents"] == parens_response.json()["amount_cents"]
    assert minus_response.json()["reportable"] == parens_response.json()["reportable"]


def test_zero_amount_is_not_reportable_without_manual_review():
    """Zero amount is not reportable alone."""
    filing = Filing("ACME", "US", "S", 0, "20260115", 0x00)
    assert_decodes_to(filing.canonical_payload(), amount_cents=0, reportable=False)


def test_zero_amount_with_manual_review_is_reportable():
    """manual_review forces reportable at zero."""
    filing = Filing("ACME", "US", "S", 0, "20260115", 0x08)
    assert_decodes_to(filing.canonical_payload(), amount_cents=0, reportable=True)


def test_negative_zero_amount_normalizes_to_plain_zero():
    """Literal negative zero normalizes to zero."""
    checksum = Filing("ACME", "US", "S", 0, "20260115", 0x00).checksum()
    payload = f"RPT7,ACME,US,S,-0,20260115,00,{checksum:02d}"
    assert_decodes_to(payload, amount_cents=0)


@pytest.mark.parametrize(("offset", "expected_reportable"), [(-1, True), (1, False)])
def test_negative_amount_magnitude_boundary_on_a_non_exact_rate_row(offset, expected_reportable):
    """Negative magnitude boundary holds on JP/D."""
    rule = SCHEMA.rule("JP", "D")
    scaled = apply_rate(rule.threshold_cents, rule.cross_border_rate)
    filing = Filing("ACME", "JP", "D", -(scaled - offset), "20260115", 0x04)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=scaled, reportable=expected_reportable
    )


def test_explicit_plus_sign_with_leading_zeros_matches_bare_amount():
    """Explicit plus sign matches bare amount."""
    rule = SCHEMA.rule("US", "S")
    bare = decode(Filing("ACME", "US", "S", rule.threshold_cents, "20260115", 0x00).canonical_payload())
    checksum = Filing("ACME", "US", "S", rule.threshold_cents, "20260115", 0x00).checksum()
    padded_payload = f"RPT7,ACME,US,S,+000{rule.threshold_cents},20260115,00,{checksum:02d}"
    padded = decode(padded_payload)
    assert bare.status_code == padded.status_code == 200
    assert bare.json() == padded.json()


def test_parenthesized_amount_with_cross_border_flag_matches_minus_sign():
    """Parenthesized amount matches minus, cross-border."""
    rule = SCHEMA.rule("UK", "D")
    scaled = apply_rate(rule.threshold_cents, rule.cross_border_rate)
    minus_sign = decode(Filing("ACME", "UK", "D", -scaled, "20260115", 0x04).canonical_payload())
    checksum = Filing("ACME", "UK", "D", -scaled, "20260115", 0x04).checksum()
    parens_payload = f"RPT7,ACME,UK,D,({scaled}),20260115,04,{checksum:02d}"
    parens = decode(parens_payload)
    assert minus_sign.status_code == parens.status_code == 200
    assert minus_sign.json() == parens.json()


def test_large_magnitude_negative_amount_on_a_retail_scaled_row():
    """Large negative amount resolves retail-scaled threshold."""
    rule = SCHEMA.rule("EU", "S")
    scaled = apply_rate(rule.threshold_cents, rule.retail_rate)
    filing = Filing("ACME", "EU", "S", -(scaled + 5_000_000_000), "20260115", 0x02)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled, reportable=True)


def test_large_magnitude_amount_on_a_scaled_non_exact_rate_row():
    """Large amount resolves scaled threshold correctly."""
    rule = SCHEMA.rule("UK", "D")
    scaled = apply_rate(apply_rate(rule.threshold_cents, rule.retail_rate), rule.cross_border_rate)
    filing = Filing("ACME", "UK", "D", scaled + 10_000_000_000, "20260115", 0x06)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled, reportable=True)


@pytest.mark.parametrize("sample_id", sorted(SCHEMA.samples))
def test_all_sample_filings_from_fixture_decode_consistently(sample_id):
    """Sample filings decode matching accepted fragments."""
    sample = SCHEMA.samples[sample_id]
    response = decode(sample.payload)
    assert response.status_code == 200, f"sample {sample_id} should decode successfully"
    body = response.json()
    for json_key, json_value in sample.fragments.items():
        assert body[json_key] == coerce_fragment_value(json_value), f"sample {sample_id} field {json_key!r}"


@pytest.mark.parametrize("flags", [3, 12])
def test_retail_flag_is_reported_from_input_bit_across_all_flag_combinations(flags):
    """Retail flag reflects input bit always."""
    filing = Filing("ACME", "US", "S", 2000000, "20260115", flags)
    assert_decodes_to(filing.canonical_payload(), retail=bool((flags >> 1) & 0x01))


def test_threshold_cents_reflects_the_cross_border_scaled_rule():
    """threshold_cents reflects cross-border scaled rule."""
    rule = SCHEMA.rule("UK", "T")
    scaled = apply_rate(rule.threshold_cents, rule.cross_border_rate)
    filing = Filing("ACME", "UK", "T", scaled, "20260115", 0x04)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled)


def test_issuer_override_threshold_supersedes_generic_rule_for_that_issuer():
    """Override threshold supersedes generic rule."""
    override = SCHEMA.override("TORQ", "US", "D")
    filing = Filing("TORQ", "US", "D", override.threshold_cents + 300000, "20260410", 0x00)
    assert_decodes_to(
        filing.canonical_payload(), reportable=True, threshold_cents=override.threshold_cents
    )


@pytest.mark.parametrize("issuer_code", ["ACME", "VESTA"])
def test_other_issuers_are_unaffected_by_a_different_issuers_override(issuer_code):
    """Other issuers unaffected by different override."""
    override = SCHEMA.override("TORQ", "US", "D")
    generic = SCHEMA.rule("US", "D")
    amount = override.threshold_cents + 300000
    assert amount < generic.threshold_cents, "fixture assumption: override amount stays under the generic rule"
    filing = Filing(issuer_code, "US", "D", amount, "20260410", 0x00)
    assert_decodes_to(
        filing.canonical_payload(), reportable=False, threshold_cents=generic.threshold_cents
    )


def test_issuer_override_cross_border_uses_its_own_multiplier_not_the_generic_one():
    """Override cross-border uses its own rate."""
    override = SCHEMA.override("TORQ", "US", "D")
    generic = SCHEMA.rule("US", "D")
    override_scaled = apply_rate(override.threshold_cents, override.cross_border_rate)
    generic_scaled = apply_rate(generic.threshold_cents, generic.cross_border_rate)
    assert override_scaled != generic_scaled, "fixture assumption: the two scaled thresholds must differ"

    torq = Filing("TORQ", "US", "D", override_scaled, "20260410", 0x04)
    assert_decodes_to(torq.canonical_payload(), threshold_cents=override_scaled, reportable=True)

    acme = Filing("ACME", "US", "D", override_scaled, "20260410", 0x04)
    assert_decodes_to(
        acme.canonical_payload(),
        threshold_cents=generic_scaled,
        reportable=override_scaled >= generic_scaled,
    )


def test_issuer_override_retail_uses_its_own_multiplier_not_the_generic_one():
    """Override retail uses its own rate."""
    override = SCHEMA.override("TORQ", "US", "D")
    generic = SCHEMA.rule("US", "D")
    override_scaled = apply_rate(override.threshold_cents, override.retail_rate)
    generic_scaled = apply_rate(generic.threshold_cents, generic.retail_rate)
    assert override_scaled != generic_scaled, "fixture assumption: the two scaled thresholds must differ"

    torq = Filing("TORQ", "US", "D", override_scaled, "20260410", 0x02)
    assert_decodes_to(torq.canonical_payload(), threshold_cents=override_scaled, reportable=True)

    acme = Filing("ACME", "US", "D", override_scaled, "20260410", 0x02)
    assert_decodes_to(
        acme.canonical_payload(),
        threshold_cents=generic_scaled,
        reportable=override_scaled >= generic_scaled,
    )


def test_issuer_override_supplies_both_rates_together_not_a_mixture():
    """Override never mixes generic rates in."""
    override = SCHEMA.override("TORQ", "US", "D")
    generic = SCHEMA.rule("US", "D")
    override_both = apply_rate(apply_rate(override.threshold_cents, override.retail_rate), override.cross_border_rate)
    mixed_retail_generic_cb = apply_rate(
        apply_rate(override.threshold_cents, generic.retail_rate), override.cross_border_rate
    )
    mixed_generic_retail_cb = apply_rate(
        apply_rate(override.threshold_cents, override.retail_rate), generic.cross_border_rate
    )
    assert len({override_both, mixed_retail_generic_cb, mixed_generic_retail_cb}) == 3, (
        "fixture assumption: all three composition paths must land on different cents"
    )

    filing = Filing("TORQ", "US", "D", override_both, "20260410", 0x06)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=override_both, reportable=True)


@pytest.mark.parametrize("flags", [0x02, 0x04, 0x06])
@pytest.mark.parametrize(("jurisdiction", "txn_type"), NON_EXACT_RATE_ROWS)
def test_composed_threshold_at_boundary_is_reportable(jurisdiction, txn_type, flags):
    """Composed threshold boundary is reportable."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    effective = rule.threshold_cents
    if flags & 0x02:
        effective = apply_rate(effective, rule.retail_rate)
    if flags & 0x04:
        effective = apply_rate(effective, rule.cross_border_rate)
    filing = Filing("ACME", jurisdiction, txn_type, effective, "20260115", flags)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=effective, reportable=True)


@pytest.mark.parametrize("flags", [0x02, 0x04, 0x06])
@pytest.mark.parametrize(("jurisdiction", "txn_type"), NON_EXACT_RATE_ROWS)
def test_composed_threshold_under_boundary_is_not_reportable(jurisdiction, txn_type, flags):
    """Composed threshold under boundary not reportable."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    effective = rule.threshold_cents
    if flags & 0x02:
        effective = apply_rate(effective, rule.retail_rate)
    if flags & 0x04:
        effective = apply_rate(effective, rule.cross_border_rate)
    filing = Filing("ACME", jurisdiction, txn_type, effective - 1, "20260115", flags)
    assert_decodes_to(filing.canonical_payload(), reportable=False)


_ORTHOGONALITY_ROWS = [("US", "S"), ("JP", "D")]


@pytest.mark.parametrize(("jurisdiction", "txn_type"), _ORTHOGONALITY_ROWS)
def test_exempt_flag_alone_does_not_disable_threshold_computation(jurisdiction, txn_type):
    """Exempt flag zeroes reportable, not threshold."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    scaled = apply_rate(rule.threshold_cents, rule.retail_rate)
    filing = Filing("ACME", jurisdiction, txn_type, scaled, "20260115", 0x03)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=scaled, exempt=True, reportable=False
    )


@pytest.mark.parametrize(("jurisdiction", "txn_type"), _ORTHOGONALITY_ROWS)
def test_manual_review_forces_reportable_when_not_exempt(jurisdiction, txn_type):
    """manual_review forces reportable under threshold."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    scaled = apply_rate(apply_rate(rule.threshold_cents, rule.retail_rate), rule.cross_border_rate)
    filing = Filing("ACME", jurisdiction, txn_type, 1, "20260115", 0x0E)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=scaled, exempt=False, reportable=True
    )


@pytest.mark.parametrize(("jurisdiction", "txn_type"), _ORTHOGONALITY_ROWS)
def test_manual_review_forces_reportable_even_when_also_exempt(jurisdiction, txn_type):
    """manual_review forces reportable even when exempt."""
    rule = SCHEMA.rule(jurisdiction, txn_type)
    scaled = apply_rate(apply_rate(rule.threshold_cents, rule.retail_rate), rule.cross_border_rate)
    filing = Filing("ACME", jurisdiction, txn_type, 1, "20260115", 0x0F)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=scaled, exempt=True, reportable=True
    )


_MATRIX_ISSUER_COMBOS = [
    ("ACME", "US", "S"),
    ("GLBL", "EU", "T"),
    ("NDEX", "UK", "P"),
    ("TORQ", "US", "D"),
    ("VESTA", "SG", "D"),
]

_MATRIX_FLAGS = [3, 15]


def _matrix_cases():
    cases = []
    for issuer_code, jurisdiction, txn_type in _MATRIX_ISSUER_COMBOS:
        threshold_cents, cross_rate, _retail = SCHEMA.effective_threshold(
            issuer_code, jurisdiction, txn_type
        )
        amount_cents = apply_rate(threshold_cents, cross_rate)
        for flags in _MATRIX_FLAGS:
            cases.append((issuer_code, jurisdiction, txn_type, amount_cents, flags))
    return cases


@pytest.mark.parametrize(
    ("issuer_code", "jurisdiction", "txn_type", "amount_cents", "flags"), _matrix_cases()
)
def test_interacting_flags_and_thresholds_match_independently_computed_decision(
    issuer_code, jurisdiction, txn_type, amount_cents, flags
):
    """Flag combinations match independently computed decision."""
    issuer = SCHEMA.issuer(issuer_code)
    threshold_cents, cross_rate, retail_rate = SCHEMA.effective_threshold(
        issuer_code, jurisdiction, txn_type
    )
    expected = expected_decision(
        issuer.exempt, threshold_cents, cross_rate, retail_rate, amount_cents, flags
    )

    filing = Filing(issuer_code, jurisdiction, txn_type, amount_cents, "20260115", flags)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200
    assert_matches_expected_decision(response.json(), expected)


@pytest.mark.parametrize(("field_index"), sorted(FIELD_NAMES_BY_INDEX)[:-1])
def test_checksum_is_sensitive_to_every_canonicalized_field(field_index):
    """Checksum is sensitive to every field."""
    filing = Filing("ACME", "US", "S", 2000000, "20260115", 0x00)
    mutated = filing.with_mutated_field(field_index)
    response = decode(mutated)
    assert response.status_code == 400, f"{FIELD_NAMES_BY_INDEX[field_index]}: {mutated}"
    assert response.json()["error"] == "checksum_mismatch"


def test_extra_trailing_field_is_rejected():
    """Extra ninth field is rejected."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    payload = filing.canonical_payload() + ",EXTRA"
    response = decode(payload)
    assert response.status_code == 400


def test_two_concatenated_records_in_one_body_is_rejected():
    """Concatenated records in one body rejected."""
    first = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    second = Filing("GLBL", "US", "S", 100, "20260115", 0x00)
    response = decode(first.canonical_payload() + "\n" + second.canonical_payload())
    assert response.status_code == 400


def test_sequential_distinct_requests_do_not_leak_state():
    """Manual-review flag does not leak state."""
    manual_review = Filing("GLBL", "US", "S", 1, "20260115", 0x08)
    ordinary = Filing("ACME", "US", "S", 1, "20260115", 0x00)

    for _ in range(3):
        mr_response = decode(manual_review.canonical_payload())
        ord_response = decode(ordinary.canonical_payload())
        assert mr_response.json()["reportable"] is True
        assert ord_response.json()["reportable"] is False
        assert ord_response.json()["manual_review"] is False


def test_interleaved_exempt_and_non_exempt_requests_do_not_leak_state():
    """Interleaving exempt filings stays isolated."""
    exempt = Filing("GLBL", "US", "S", 5000000, "20260115", 0x00)
    plain = Filing("ACME", "US", "S", 5000000, "20260115", 0x00)
    for _ in range(4):
        exempt_response = decode(exempt.canonical_payload())
        plain_response = decode(plain.canonical_payload())
        assert exempt_response.json()["exempt"] is True
        assert exempt_response.json()["reportable"] is False
        assert plain_response.json()["exempt"] is False
        assert plain_response.json()["reportable"] is True


def test_interleaved_cross_border_and_plain_requests_do_not_leak_state():
    """Interleaving cross-border filings stays isolated."""
    rule = SCHEMA.rule("UK", "T")
    scaled = apply_rate(rule.threshold_cents, rule.cross_border_rate)
    cross_border = Filing("ACME", "UK", "T", scaled, "20260115", 0x04)
    plain = Filing("ACME", "UK", "T", rule.threshold_cents, "20260115", 0x00)
    for _ in range(4):
        cb_response = decode(cross_border.canonical_payload())
        plain_response = decode(plain.canonical_payload())
        assert cb_response.json()["threshold_cents"] == scaled
        assert plain_response.json()["threshold_cents"] == rule.threshold_cents


def test_interleaved_rejected_and_accepted_requests_do_not_leak_state():
    """Rejected request never contaminates next accepted."""
    rejected = "RPT7,ACME,US,S,not-a-number,20260115,00,00"
    accepted = Filing("ACME", "US", "S", 1000000, "20260115", 0x00)
    for _ in range(3):
        bad_response = decode(rejected)
        good_response = decode(accepted.canonical_payload())
        assert bad_response.status_code == 400
        assert good_response.status_code == 200
        assert good_response.json()["reportable"] is True


def test_interleaved_temporal_eras_do_not_leak_state():
    """QURO eras interleave without leaking state."""
    early = Filing("QURO", "US", "D", 900000, "20250615", 0x00)
    late = Filing("QURO", "US", "D", 1000000, "20261001", 0x00)
    for _ in range(3):
        early_response = decode(early.canonical_payload())
        late_response = decode(late.canonical_payload())
        assert early_response.json()["threshold_cents"] == 900000
        assert late_response.json()["threshold_cents"] == 1000000


def test_rapid_sequential_requests_across_many_issuers_stay_isolated():
    """Rapid requests across issuers stay isolated."""
    issuers = ["ACME", "GLBL", "NDEX", "TORQ", "VESTA", "QURO"]
    responses = []
    for issuer_code in issuers:
        filing = Filing(issuer_code, "US", "S", 1, "20260115", 0x00)
        responses.append(decode(filing.canonical_payload()))
    for issuer_code, response in zip(issuers, responses):
        assert response.status_code == 200
        assert response.json()["issuer_code"] == issuer_code


@pytest.mark.parametrize(
    "variant_pair",
    [
        (0, 1),
        (6, 11),
        (2, 7),
        (5, 10),
    ],
)
def test_response_body_is_byte_identical_across_equivalent_noisy_encodings(variant_pair):
    """Noisy encodings produce byte-identical response bodies."""
    filing = Filing("NDEX", "EU", "T", 375000, "20260201", 0x00)
    first_variant, second_variant = variant_pair
    first = decode(filing.noisy_payload(first_variant))
    second = decode(filing.noisy_payload(second_variant))
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


def _alternate_server_fixture(build_database, topology_name):
    @pytest.fixture(scope="module")
    def _server(tmp_path_factory):
        alt_dir = tmp_path_factory.mktemp(topology_name)
        db_path = alt_dir / f"{topology_name}.db"
        build_database(db_path)
        process, server = launch_alternate_server(db_path)
        try:
            yield server
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()

    return _server


topology_a_server = _alternate_server_fixture(build_topology_a_database, "topology_a")


def test_alternate_dataset_instance_starts(topology_a_server):
    """Alternate dataset instance starts cleanly."""
    assert topology_a_server.startup_error is None, topology_a_server.startup_error


@pytest.mark.parametrize(
    ("issuer_code", "jurisdiction", "txn_type", "amount_cents", "flags"),
    [
        ("ZETA", "CA", "S", 1750000, 0x00),
        ("ZETA", "CA", "S", 1749999, 0x00),
        ("ZETA", "CA", "D", 900000, 0x00),
        ("ZETA", "CA", "D", 899999, 0x00),
        ("ZETA", "CA", "D", 360000, 0x04),
        ("QRST", "JP", "T", 50_000_000, 0x00),
        ("QRST", "JP", "T", 1, 0x08),
    ],
)
def test_topology_a_is_resolved_correctly_not_hardcoded(
    topology_a_server, issuer_code, jurisdiction, txn_type, amount_cents, flags
):
    """Topology A resolves correctly, not hardcoded."""
    exempt_org = issuer_code == "QRST"
    if (issuer_code, jurisdiction, txn_type) == ("ZETA", "CA", "D"):
        threshold_cents = 900000
        cross_rate, retail_rate = schema_data.Rate(2, 5), schema_data.Rate(7, 8)
    else:
        thresholds = {
            ("CA", "S"): (1750000, schema_data.Rate(13, 20), schema_data.Rate(3, 4)),
            ("JP", "T"): (620000, schema_data.Rate(7, 10), schema_data.Rate(5, 8)),
        }
        threshold_cents, cross_rate, retail_rate = thresholds[(jurisdiction, txn_type)]
    expected = expected_decision(
        exempt_org, threshold_cents, cross_rate, retail_rate, amount_cents, flags
    )

    filing = Filing(issuer_code, jurisdiction, txn_type, amount_cents, "20260115", flags)
    response = decode(filing.canonical_payload(), base_url=topology_a_server.base_url)
    assert response.status_code == 200
    assert_matches_expected_decision(response.json(), expected)


def test_topology_a_rejects_issuers_from_the_original_dataset(topology_a_server):
    """Original issuers rejected on topology A."""
    filing = Filing("ACME", "US", "S", 999999, "20260115", 0x00)
    response = decode(filing.canonical_payload(), base_url=topology_a_server.base_url)
    assert response.status_code == 400
    assert response.json()["error"] == "unknown_issuer"


topology_b_server = _alternate_server_fixture(build_topology_b_database, "topology_b")


def test_topology_b_instance_starts(topology_b_server):
    """Topology B instance starts cleanly."""
    assert topology_b_server.startup_error is None, topology_b_server.startup_error


@pytest.mark.parametrize(
    ("jurisdiction", "txn_type", "amount_cents", "flags", "expected_threshold", "expected_reportable"),
    [
        ("US", "S", 900000, 0x00, 900000, True),
        ("US", "S", 899999, 0x00, 900000, False),
        ("EU", "D", 1800000, 0x00, 1800000, True),
        ("EU", "D", 1799999, 0x00, 1800000, False),
        ("EU", "D", 594000, 0x04, 594000, True),
        ("EU", "D", 593999, 0x04, 594000, False),
    ],
)
def test_topology_b_override_thresholds_are_issuer_and_jurisdiction_specific(
    topology_b_server, jurisdiction, txn_type, amount_cents, flags, expected_threshold, expected_reportable
):
    """NOVA overrides apply per jurisdiction correctly."""
    filing = Filing("NOVA", jurisdiction, txn_type, amount_cents, "20260115", flags)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=expected_threshold,
        reportable=expected_reportable,
    )


@pytest.mark.parametrize("amount_cents", [2200000])
def test_topology_b_override_does_not_leak_to_other_issuers_same_jurisdiction(
    topology_b_server, amount_cents
):
    """HALO never inherits NOVA's override."""
    filing = Filing("HALO", "US", "S", amount_cents, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=2200000,
        exempt=True,
        reportable=False,
    )


@pytest.mark.parametrize(("amount_cents", "expected_reportable"), [(5000000, True), (4999999, False)])
def test_topology_b_generic_rule_applies_without_override(
    topology_b_server, amount_cents, expected_reportable
):
    """ECHO resolves the plain generic rule."""
    filing = Filing("ECHO", "EU", "D", amount_cents, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=5000000,
        reportable=expected_reportable,
    )


def test_topology_b_unscaled_override_threshold_is_the_override_base(topology_b_server):
    """Unscaled override threshold is its base."""
    filing = Filing("NOVA", "JP", "T", 600002, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=600002,
        reportable=True,
    )


@pytest.mark.parametrize("amount_cents", [1000003])
def test_topology_b_override_does_not_leak_to_an_issuer_in_the_same_jurisdiction_and_type(
    topology_b_server, amount_cents
):
    """ECHO never inherits NOVA's JP/T override."""
    filing = Filing("ECHO", "JP", "T", amount_cents, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=1000003,
        reportable=amount_cents >= 1000003,
    )


_TOPOLOGY_B_BOUNDARY_ROWS = [
    ("ECHO", "SG", "P", "20260115", 0x04, 241643, 241643, True),
    ("ECHO", "SG", "P", "20260115", 0x04, 241642, 241643, False),
    ("ECHO", "JP", "T", "20260115", 0x04, 250000, 250001, False),
    ("ECHO", "JP", "T", "20260115", 0x04, 250001, 250001, True),
    ("NOVA", "JP", "T", "20260115", 0x04, 450001, 450002, False),
    ("NOVA", "JP", "T", "20260115", 0x04, 450002, 450002, True),
    ("ECHO", "CA", "S", "20260115", 0x06, 250000, 250001, False),
    ("ECHO", "CA", "S", "20260115", 0x06, 250001, 250001, True),
    ("ECHO", "CA", "P", "20261101", 0x06, 499999, 500000, False),
    ("ECHO", "CA", "P", "20261101", 0x06, 500000, 500000, True),
    ("NOVA", "CA", "S", "20260115", 0x02, 700000, 700001, False),
    ("NOVA", "CA", "S", "20260115", 0x02, 700001, 700001, True),
    ("ECHO", "JP", "D", "20260115", 0x04, 1499999999, 1500000000, False),
    ("ECHO", "JP", "D", "20260115", 0x04, 1500000000, 1500000000, True),
    ("ECHO", "CA", "D", "20260115", 0x06, 517500034, 517500035, False),
    ("ECHO", "CA", "D", "20260115", 0x06, 517500035, 517500035, True),
]


@pytest.mark.parametrize(
    (
        "issuer_code",
        "jurisdiction",
        "txn_type",
        "date8",
        "flags",
        "amount_cents",
        "expected_threshold",
        "expected_reportable",
    ),
    _TOPOLOGY_B_BOUNDARY_ROWS,
)
def test_topology_b_boundary_rounding_matches_expected_threshold_and_reportable(
    topology_b_server,
    issuer_code,
    jurisdiction,
    txn_type,
    date8,
    flags,
    amount_cents,
    expected_threshold,
    expected_reportable,
):
    """Scaled thresholds round and compose to the filed cent."""
    filing = Filing(issuer_code, jurisdiction, txn_type, amount_cents, date8, flags)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_b_server.base_url,
        threshold_cents=expected_threshold,
        reportable=expected_reportable,
    )


topology_c_server = _alternate_server_fixture(build_topology_c_database, "topology_c")


def test_topology_c_instance_starts(topology_c_server):
    """Topology C instance starts cleanly."""
    assert topology_c_server.startup_error is None, topology_c_server.startup_error


def test_topology_c_issuer_name_with_special_characters_is_valid_json(topology_c_server):
    """Quoted issuer name still valid JSON."""
    filing = Filing("QUOT", "US", "S", 999999, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_c_server.base_url,
        issuer_name='Acme "Premier" Holdings\\Group',
    )


@pytest.mark.parametrize(
    ("amount_cents", "expected_reportable"), [(374999, False), (375000, True)]
)
def test_topology_c_override_is_matched_case_insensitively(
    topology_c_server, amount_cents, expected_reportable
):
    """Lowercase-stored override matched case-insensitively."""
    filing = Filing("LOWJ", "EU", "D", amount_cents, "20260115", 0x06)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_c_server.base_url,
        threshold_cents=375000,
        reportable=expected_reportable,
    )


@pytest.mark.parametrize(
    ("amount_cents", "expected_reportable"), [(499999, False), (500000, True)]
)
def test_topology_c_generic_rule_is_matched_case_insensitively(
    topology_c_server, amount_cents, expected_reportable
):
    """Lowercase-stored generic rule matched case-insensitively."""
    filing = Filing("NOOV", "EU", "D", amount_cents, "20260115", 0x06)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_c_server.base_url,
        threshold_cents=500000,
        reportable=expected_reportable,
    )


topology_d_server = _alternate_server_fixture(build_topology_d_database, "topology_d")


def test_topology_d_instance_starts(topology_d_server):
    """Topology D instance starts cleanly."""
    assert topology_d_server.startup_error is None, topology_d_server.startup_error


def test_topology_d_stepwise_composition_under_boundary_is_not_reportable(topology_d_server):
    """Stepwise composition under boundary not reportable."""
    threshold, cross_rate, retail_rate = TOPOLOGY_D_OVERRIDE
    stepwise = apply_rate(apply_rate(threshold, retail_rate), cross_rate)
    filing = Filing("ZQNEG1", "EU", "X", stepwise - 1, "20260115", 0x06)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_d_server.base_url,
        threshold_cents=stepwise,
        reportable=False,
    )


def test_topology_d_stepwise_composition_at_boundary_is_reportable(topology_d_server):
    """Stepwise composition boundary is reportable."""
    threshold, cross_rate, retail_rate = TOPOLOGY_D_OVERRIDE
    stepwise = apply_rate(apply_rate(threshold, retail_rate), cross_rate)
    filing = Filing("ZQNEG1", "EU", "X", stepwise, "20260115", 0x06)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_d_server.base_url,
        threshold_cents=stepwise,
        reportable=True,
    )


def test_topology_d_manual_review_forces_reportable_on_tiny_negative_amount(topology_d_server):
    """manual_review forces reportable on tiny negative."""
    filing = Filing("ZQNEG1", "EU", "X", -50000, "20260115", 0x0E)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_d_server.base_url,
        amount_cents=-50000,
        reportable=True,
    )


def test_topology_d_retail_only_boundary_is_reportable_at_threshold(topology_d_server):
    """Retail-only boundary is reportable at threshold."""
    threshold, _cross, retail = TOPOLOGY_D_OVERRIDE
    scaled = apply_rate(threshold, retail)
    filing = Filing("ZQNEG1", "EU", "X", scaled, "20260115", 0x02)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_d_server.base_url,
        threshold_cents=scaled,
        reportable=True,
    )


def test_topology_d_cross_border_only_boundary_is_not_reportable_under(topology_d_server):
    """Cross-border-only boundary not reportable under threshold."""
    threshold, cross, _retail = TOPOLOGY_D_OVERRIDE
    scaled = apply_rate(threshold, cross)
    filing = Filing("ZQNEG1", "EU", "X", scaled - 1, "20260115", 0x04)
    assert_decodes_to(
        filing.canonical_payload(), base_url=topology_d_server.base_url, reportable=False
    )


def test_topology_d_exempt_and_reportable_are_independent_fields(topology_d_server):
    """exempt and reportable can be independent."""
    filing = Filing("ZQNEG1", "EU", "X", 50000000, "20260115", 0x0F)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_d_server.base_url,
        exempt=True,
        reportable=True,
    )


topology_e_server = _alternate_server_fixture(build_topology_e_database, "topology_e")


def test_topology_e_instance_starts(topology_e_server):
    """Topology E instance starts cleanly."""
    assert topology_e_server.startup_error is None, topology_e_server.startup_error


def test_topology_e_case_folded_override_resolves_with_escaped_name(topology_e_server):
    """Case-folded override resolves with escaped name."""
    filing = Filing("ZQJSON1", "EU", "W", 600000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name=TOPOLOGY_E_QUOTED_NAME,
        threshold_cents=500000,
        reportable=True,
    )


def test_topology_e_second_issuer_resolves_its_own_override_only(topology_e_server):
    """Second issuer resolves only its override."""
    filing = Filing("ZQJSON2", "EU", "W", 999000000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        threshold_cents=999000000,
        reportable=True,
    )


def test_topology_e_checksum_still_covers_flags_amid_case_folding(topology_e_server):
    """Checksum still catches flipped flags digit."""
    filing = Filing("ZQJSON1", "EU", "W", 600000, "20260115", 0x00)
    tampered = filing.with_mutated_field(6)
    response = decode(tampered, base_url=topology_e_server.base_url)
    assert response.status_code == 400
    assert response.json()["error"] == "checksum_mismatch"


def test_topology_e_control_character_in_name_round_trips_through_json(topology_e_server):
    """Embedded control character round-trips through JSON."""
    filing = Filing("ZQCTRL", "EU", "W", 1500000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name="Line1\nLine2 Corp",
    )


def test_topology_e_embedded_tab_round_trips_through_json(topology_e_server):
    """Embedded tab character round-trips through JSON."""
    filing = Filing("ZQTAB", "EU", "W", 1500000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name="Column1\tColumn2 Corp",
    )


def test_topology_e_unicode_name_is_preserved_byte_correctly(topology_e_server):
    """Unicode name bytes survive JSON encoding."""
    filing = Filing("ZQUNI", "EU", "W", 1500000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name="Société Générale Ñoño 日本 Corp",
    )


def test_topology_e_response_body_parses_as_a_single_json_object(topology_e_server):
    """Response body parses as one object."""
    filing = Filing("ZQJSON1", "EU", "W", 600000, "20260115", 0x00)
    response = decode(filing.canonical_payload(), base_url=topology_e_server.base_url)
    assert response.status_code == 200
    decoded = json.loads(response.text)
    assert isinstance(decoded, dict)
    assert decoded["issuer_name"] == TOPOLOGY_E_QUOTED_NAME


def test_topology_e_lowercase_issuer_and_override_resolve_in_distinct_jurisdiction(topology_e_server):
    """Lowercase issuer resolves override in US/W."""
    filing = Filing("LOWOV", "US", "W", 700000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        threshold_cents=700000,
        reportable=True,
    )


def test_topology_e_escaped_name_survives_alongside_rate_scaling(topology_e_server):
    """Escaped name survives alongside scaled threshold."""
    scaled = apply_rate(500000, schema_data.Rate(1, 2))
    filing = Filing("ZQJSON1", "EU", "W", scaled, "20260115", 0x02)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name=TOPOLOGY_E_QUOTED_NAME,
        threshold_cents=scaled,
        reportable=True,
    )


def test_topology_e_unicode_name_survives_alongside_case_folded_generic_rule(topology_e_server):
    """Unicode name survives case-folded generic rule."""
    filing = Filing("ZQUNI", "EU", "W", 1000000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        issuer_name="Société Générale Ñoño 日本 Corp",
        threshold_cents=1000000,
        reportable=True,
    )


def test_topology_e_lowercase_issuer_generic_rule_fallback(topology_e_server):
    """Lowercase issuer falls back to generic."""
    filing = Filing("LOWOV", "EU", "W", 500000, "20260115", 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_e_server.base_url,
        threshold_cents=1000000,
        reportable=False,
    )


@pytest.mark.parametrize(
    ("amount_cents", "expected_reportable"), [(3588890548, False), (3588890549, True)]
)
def test_deep_registry_filer_files_under_its_own_rate_schedule(amount_cents, expected_reportable):
    """Deep filer resolves its own rate."""
    filing = Filing(generated_filer_code(200000), "SG", "T", amount_cents, "20261001", 0x04)
    response = decode(filing.canonical_payload())
    assert response.status_code == 200, f"deep registry filer did not resolve: {response.text}"
    body = response.json()
    assert body["threshold_cents"] == 3588890549
    assert body["reportable"] is expected_reportable


def _quro_effective(filing_date8):
    resolved = resolve_temporal_override(QURO_US_D_VERSIONS, filing_date8)
    if resolved is not None:
        return resolved
    rule = SCHEMA.rule("US", "D")
    return rule.threshold_cents, rule.cross_border_rate, rule.retail_rate


QURO_ERA_DATES = ["20241231", "20250615", "20260601", "20261231"]


def _temporal_override_helpers(
    issuer_code, jurisdiction, txn_type, effective, versions, generic_threshold
):
    def resolve_base_url(alt_server):
        return BASE_URL if alt_server is None else alt_server.base_url

    def retail_at_threshold(alt_server, filing_date8):
        threshold, _cross, retail = effective(filing_date8)
        scaled = apply_rate(threshold, retail)
        filing = Filing(issuer_code, jurisdiction, txn_type, scaled, filing_date8, 0x02)
        assert_decodes_to(
            filing.canonical_payload(),
            base_url=resolve_base_url(alt_server),
            threshold_cents=scaled,
            reportable=True,
        )

    def retail_under_threshold(alt_server, filing_date8):
        threshold, _cross, retail = effective(filing_date8)
        scaled = apply_rate(threshold, retail)
        filing = Filing(issuer_code, jurisdiction, txn_type, scaled - 1, filing_date8, 0x02)
        assert_decodes_to(
            filing.canonical_payload(), base_url=resolve_base_url(alt_server), reportable=False
        )

    def both_flags_at_threshold(alt_server, filing_date8):
        threshold, cross, retail = effective(filing_date8)
        scaled = apply_rate(apply_rate(threshold, retail), cross)
        filing = Filing(issuer_code, jurisdiction, txn_type, scaled, filing_date8, 0x06)
        assert_decodes_to(
            filing.canonical_payload(),
            base_url=resolve_base_url(alt_server),
            threshold_cents=scaled,
            reportable=True,
        )

    def both_flags_under_threshold(alt_server, filing_date8):
        threshold, cross, retail = effective(filing_date8)
        scaled = apply_rate(apply_rate(threshold, retail), cross)
        filing = Filing(issuer_code, jurisdiction, txn_type, scaled - 1, filing_date8, 0x06)
        assert_decodes_to(
            filing.canonical_payload(), base_url=resolve_base_url(alt_server), reportable=False
        )

    def exact_date_boundary(alt_server, filing_date8, expected_version_index):
        if expected_version_index is None:
            expected_threshold = generic_threshold
        else:
            expected_threshold = versions[expected_version_index][1]
        filing = Filing(issuer_code, jurisdiction, txn_type, expected_threshold, filing_date8, 0x00)
        assert_decodes_to(
            filing.canonical_payload(),
            base_url=resolve_base_url(alt_server),
            threshold_cents=expected_threshold,
        )

    def manual_review_before_any_version(alt_server):
        filing = Filing(issuer_code, jurisdiction, txn_type, 1, "20200101", 0x08)
        assert_decodes_to(
            filing.canonical_payload(),
            base_url=resolve_base_url(alt_server),
            reportable=True,
            threshold_cents=generic_threshold,
        )

    return SimpleNamespace(
        retail_at_threshold=retail_at_threshold,
        retail_under_threshold=retail_under_threshold,
        both_flags_at_threshold=both_flags_at_threshold,
        both_flags_under_threshold=both_flags_under_threshold,
        exact_date_boundary=exact_date_boundary,
        manual_review_before_any_version=manual_review_before_any_version,
    )


_quro_helpers = _temporal_override_helpers(
    "QURO", "US", "D", _quro_effective, QURO_US_D_VERSIONS, SCHEMA.rule("US", "D").threshold_cents
)


@pytest.mark.parametrize("filing_date8", QURO_ERA_DATES)
def test_quro_retail_flag_boundary_at_threshold_is_reportable(filing_date8):
    """QURO retail-scaled boundary is reportable."""
    _quro_helpers.retail_at_threshold(None, filing_date8)


@pytest.mark.parametrize("filing_date8", QURO_ERA_DATES)
def test_quro_retail_flag_boundary_under_threshold_is_not_reportable(filing_date8):
    """QURO retail boundary not reportable under."""
    _quro_helpers.retail_under_threshold(None, filing_date8)


@pytest.mark.parametrize("filing_date8", QURO_ERA_DATES)
def test_quro_both_flags_boundary_at_threshold_is_reportable(filing_date8):
    """QURO both-flag boundary is reportable."""
    _quro_helpers.both_flags_at_threshold(None, filing_date8)


@pytest.mark.parametrize("filing_date8", QURO_ERA_DATES)
def test_quro_both_flags_boundary_under_threshold_is_not_reportable(filing_date8):
    """QURO both-flag boundary not reportable under."""
    _quro_helpers.both_flags_under_threshold(None, filing_date8)


@pytest.mark.parametrize(
    ("filing_date8", "expected_version_index"),
    [
        ("20241231", None),
        ("20250101", 0),
        ("20260228", 0),
        ("20260301", 1),
        ("20260831", 1),
        ("20260901", 2),
        ("20261225", 2),
    ],
)
def test_quro_exact_date_boundary_selects_correct_version(filing_date8, expected_version_index):
    """QURO resolves correct version at boundary."""
    _quro_helpers.exact_date_boundary(None, filing_date8, expected_version_index)


@pytest.mark.parametrize("filing_date8", ["19990101", "20000101"])
def test_quro_falls_back_to_generic_arbitrarily_far_before_v1(filing_date8):
    """QURO falls back to generic early."""
    rule = SCHEMA.rule("US", "D")
    filing = Filing("QURO", "US", "D", rule.threshold_cents, filing_date8, 0x00)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=rule.threshold_cents)


def test_quro_manual_review_forces_reportable_before_any_version_started():
    """manual_review forces reportable before any version."""
    _quro_helpers.manual_review_before_any_version(None)


def test_quro_manual_review_with_retail_flag_at_v1_still_computes_threshold():
    """manual_review with retail still computes threshold."""
    threshold, _cross, retail = _quro_effective("20250615")
    scaled = apply_rate(threshold, retail)
    filing = Filing("QURO", "US", "D", 1, "20250615", 0x0A)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled, reportable=True)


def test_quro_exempt_flag_at_a_mid_version_date():
    """QURO exempt flag suppresses reportable, v2."""
    threshold, cross, _retail = _quro_effective("20260601")
    scaled = apply_rate(threshold, cross)
    filing = Filing("QURO", "US", "D", scaled, "20260601", 0x05)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=scaled, exempt=True, reportable=False
    )


def test_quro_v3_never_mixes_v2_rate_with_v3_threshold():
    """QURO v3 never resolves v2's rate."""
    _v2_threshold, v2_cross, _v2_retail = QURO_US_D_VERSIONS[1][1:]
    v3_threshold, v3_cross, _v3_retail = QURO_US_D_VERSIONS[2][1:]
    correct = apply_rate(v3_threshold, v3_cross)
    wrong_mix = apply_rate(v3_threshold, v2_cross)
    assert correct != wrong_mix, "fixture assumption: mixing v2's rate must differ"
    filing = Filing("QURO", "US", "D", correct, "20261001", 0x04)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=correct, reportable=True)


@pytest.mark.parametrize(("amount_cents", "expected_reportable"), [(5199996, True), (5199995, False)])
def test_deep_filer_original_override_before_amendment(amount_cents, expected_reportable):
    """Deep filer resolves original override, pre-amendment."""
    filing = Filing(DEEP_FILER_AMENDMENT_ISSUER, "US", "S", amount_cents, "20260101", 0x00)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=5199996, reportable=expected_reportable
    )


@pytest.mark.parametrize(("amount_cents", "expected_reportable"), [(5500000, True), (5499999, False)])
def test_deep_filer_amended_override_on_and_after_amendment_date(amount_cents, expected_reportable):
    """Deep filer resolves amended override after."""
    filing = Filing(DEEP_FILER_AMENDMENT_ISSUER, "US", "S", amount_cents, "20260601", 0x00)
    assert_decodes_to(
        filing.canonical_payload(), threshold_cents=5500000, reportable=expected_reportable
    )


def test_deep_filer_amendment_does_not_affect_other_slots():
    """Deep filer's other slots stay unaffected."""
    threshold, _cross, _retail = generated_override(50000, "US", "D")
    filing = Filing(DEEP_FILER_AMENDMENT_ISSUER, "US", "D", threshold, "20260601", 0x00)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=threshold)


def test_deep_filer_amendment_does_not_affect_a_neighboring_filer():
    """Neighboring filer's override stays unaffected."""
    threshold, _cross, _retail = generated_override(49999, "US", "S")
    filing = Filing(generated_filer_code(49999), "US", "S", threshold, "20260601", 0x00)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=threshold)


def test_deep_filer_amended_cross_border_scaling():
    """Deep filer's amendment scales cross-border."""
    scaled = apply_rate(5500000, schema_data.Rate(3, 5))
    filing = Filing(DEEP_FILER_AMENDMENT_ISSUER, "US", "S", scaled, "20260601", 0x04)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled, reportable=True)


def test_deep_filer_amended_retail_scaling():
    """Deep filer's amendment scales under retail."""
    scaled = apply_rate(5500000, schema_data.Rate(2, 3))
    filing = Filing(DEEP_FILER_AMENDMENT_ISSUER, "US", "S", scaled, "20260601", 0x02)
    assert_decodes_to(filing.canonical_payload(), threshold_cents=scaled, reportable=True)


topology_f_server = _alternate_server_fixture(build_topology_f_database, "topology_f")


def test_topology_f_instance_starts(topology_f_server):
    """Topology F instance starts cleanly."""
    assert topology_f_server.startup_error is None, topology_f_server.startup_error


def _raft_effective(filing_date8):
    resolved = resolve_temporal_override(RAFT_CA_W_VERSIONS, filing_date8)
    return resolved if resolved is not None else RAFT_CA_W_GENERIC


RAFT_ERA_DATES = ["20240101", "20241001", "20260101"]

_raft_helpers = _temporal_override_helpers(
    "RAFT", "CA", "W", _raft_effective, RAFT_CA_W_VERSIONS, RAFT_CA_W_GENERIC[0]
)


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_retail_boundary_at_threshold(topology_f_server, filing_date8):
    """RAFT retail-scaled boundary is reportable."""
    _raft_helpers.retail_at_threshold(topology_f_server, filing_date8)


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_retail_boundary_under_threshold(topology_f_server, filing_date8):
    """RAFT retail boundary not reportable under."""
    _raft_helpers.retail_under_threshold(topology_f_server, filing_date8)


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_cross_border_boundary_at_threshold(topology_f_server, filing_date8):
    """RAFT cross-border-scaled boundary is reportable."""
    threshold, cross, _retail = _raft_effective(filing_date8)
    scaled = apply_rate(threshold, cross)
    filing = Filing("RAFT", "CA", "W", scaled, filing_date8, 0x04)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_f_server.base_url,
        threshold_cents=scaled,
        reportable=True,
    )


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_cross_border_boundary_under_threshold(topology_f_server, filing_date8):
    """RAFT cross-border boundary not reportable under."""
    threshold, cross, _retail = _raft_effective(filing_date8)
    scaled = apply_rate(threshold, cross)
    filing = Filing("RAFT", "CA", "W", scaled - 1, filing_date8, 0x04)
    assert_decodes_to(
        filing.canonical_payload(), base_url=topology_f_server.base_url, reportable=False
    )


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_both_flags_boundary_at_threshold(topology_f_server, filing_date8):
    """RAFT both-flag boundary is reportable."""
    _raft_helpers.both_flags_at_threshold(topology_f_server, filing_date8)


@pytest.mark.parametrize("filing_date8", RAFT_ERA_DATES)
def test_topology_f_raft_both_flags_boundary_under_threshold(topology_f_server, filing_date8):
    """RAFT both-flag boundary not reportable under."""
    _raft_helpers.both_flags_under_threshold(topology_f_server, filing_date8)


@pytest.mark.parametrize(
    ("filing_date8", "expected_version_index"),
    [
        ("20240101", None),
        ("20240531", None),
        ("20240601", 0),
        ("20250601", 0),
        ("20250901", 1),
        ("20261231", 1),
    ],
)
def test_topology_f_raft_exact_date_boundary_selects_correct_version(
    topology_f_server, filing_date8, expected_version_index
):
    """RAFT resolves correct version at boundary."""
    _raft_helpers.exact_date_boundary(topology_f_server, filing_date8, expected_version_index)


def test_topology_f_raft_manual_review_before_any_version_started(topology_f_server):
    """manual_review forces reportable before RAFT version."""
    _raft_helpers.manual_review_before_any_version(topology_f_server)


@pytest.mark.parametrize(("filing_date8", "expected_reportable"), [(RAFT_ERA_DATES[0], False), (RAFT_ERA_DATES[0], True)])
def test_topology_f_noko_always_resolves_generic_rule(topology_f_server, filing_date8, expected_reportable):
    """NOKO always resolves the generic rule."""
    amount = RAFT_CA_W_GENERIC[0] if expected_reportable else RAFT_CA_W_GENERIC[0] - 1
    filing = Filing("NOKO", "CA", "W", amount, filing_date8, 0x00)
    assert_decodes_to(
        filing.canonical_payload(),
        base_url=topology_f_server.base_url,
        threshold_cents=RAFT_CA_W_GENERIC[0],
        reportable=expected_reportable,
    )


def _zqmix_effective(filing_date8):
    resolved = resolve_temporal_override(ZQMIX_MX_Z_VERSIONS, filing_date8)
    return resolved if resolved is not None else ZQMIX_MX_Z_GENERIC


ZQMIX_ERA_DATES = ["20230101", "20240601", "20260101"]


@pytest.mark.parametrize("filing_date8", ZQMIX_ERA_DATES)
def test_topology_f_zqmix_case_folded_temporal_resolution_at_threshold(topology_f_server, filing_date8):
    """Lowercase temporal override resolves at threshold."""
    threshold, cross, retail = _zqmix_effective(filing_date8)
    scaled = apply_rate(apply_rate(threshold, retail), cross)
    filing = Filing("ZQMIX", "MX", "Z", scaled, filing_date8, 0x06)
    response = decode(filing.canonical_payload(), base_url=topology_f_server.base_url)
    assert response.status_code == 200
    body = response.json()
    assert body["threshold_cents"] == scaled
    assert body["reportable"] is True


@pytest.mark.parametrize("filing_date8", ZQMIX_ERA_DATES)
def test_topology_f_zqmix_case_folded_temporal_resolution_under_threshold(topology_f_server, filing_date8):
    """Lowercase temporal override resolves under threshold."""
    threshold, cross, retail = _zqmix_effective(filing_date8)
    scaled = apply_rate(apply_rate(threshold, retail), cross)
    filing = Filing("ZQMIX", "MX", "Z", scaled - 1, filing_date8, 0x06)
    response = decode(filing.canonical_payload(), base_url=topology_f_server.base_url)
    assert response.status_code == 200
    assert response.json()["reportable"] is False


@pytest.mark.parametrize("sample_id", [16, 26, 30])
def test_fresh_process_against_primary_database_matches_session_instance(sample_id):
    """Fresh process matches session instance exactly."""
    port = held_out_data._free_tcp_port()
    env = {key: value for key, value in os.environ.items() if not key.startswith("RPT7_")}
    env["RPT7_PORT"] = str(port)
    process = subprocess.Popen([SERVER_BINARY], env=env, **privilege_drop_kwargs())
    try:
        fresh_base_url = f"http://127.0.0.1:{port}"
        startup_error = conftest.wait_for_health(fresh_base_url)
        assert startup_error is None, startup_error

        sample = SCHEMA.samples[sample_id]
        primary_response = decode(sample.payload)
        fresh_response = decode(sample.payload, base_url=fresh_base_url)
        assert primary_response.status_code == fresh_response.status_code == 200
        assert primary_response.json() == fresh_response.json()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()


_MONOTONICITY_COMBOS = [
    ("ACME", "US", "S"),
    ("TORQ", "US", "D"),
    ("VESTA", "UK", "P"),
    ("NDEX", "EU", "T"),
    ("ACME", "JP", "D"),
    ("GLBL", "SG", "D"),
    ("NDEX", "UK", "D"),
]


@pytest.mark.parametrize(("issuer_code", "jurisdiction", "txn_type"), _MONOTONICITY_COMBOS)
def test_reportable_is_monotonic_in_amount(issuer_code, jurisdiction, txn_type):
    """Reportable is monotonic as amount increases."""
    threshold_cents, _cross_rate, _retail = SCHEMA.effective_threshold(
        issuer_code, jurisdiction, txn_type
    )
    offsets = [-2, -1, 0, 1, 2]
    results = []
    for offset in offsets:
        filing = Filing(issuer_code, jurisdiction, txn_type, threshold_cents + offset, "20260115", 0x00)
        response = decode(filing.canonical_payload())
        assert response.status_code == 200
        results.append(response.json()["reportable"])
    for earlier, later in itertools.pairwise(results):
        assert (not earlier) or later, f"reportable flipped back to false: {list(zip(offsets, results, strict=True))}"


@pytest.mark.parametrize("sample_id", [1, 12, 22, 26, 30])
def test_repeated_identical_decodes_are_byte_identical(sample_id):
    """Decoding the same payload twice matches."""
    sample = SCHEMA.samples[sample_id]
    first = decode(sample.payload)
    second = decode(sample.payload)
    assert first.status_code == second.status_code == 200
    assert first.text == second.text
