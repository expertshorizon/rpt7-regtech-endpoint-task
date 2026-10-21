from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SCHEMA_PATH = "/tests/fixtures/schema.sql"

_ISSUER_ROW = re.compile(r"\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)\s*\)")
_RULE_ROW = re.compile(
    r"\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)\s*,"
    r"\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)"
)
_OVERRIDE_ROW = re.compile(
    r"\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(\d+)\s*,"
    r"\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)"
)
_SAMPLE_FILING_ROW = re.compile(r"\(\s*(\d+)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)")
_ACCEPTED_FRAGMENT_ROW = re.compile(r"\(\s*(\d+)\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)")


@dataclass(frozen=True)
class Rate:

    num: int
    den: int


@dataclass(frozen=True)
class Issuer:
    code: str
    name: str
    exempt: bool


@dataclass(frozen=True)
class Rule:
    jurisdiction: str
    txn_type: str
    threshold_cents: int
    cross_border_rate: Rate
    retail_rate: Rate


@dataclass(frozen=True)
class Override:
    issuer_code: str
    jurisdiction: str
    txn_type: str
    threshold_cents: int
    cross_border_rate: Rate
    retail_rate: Rate


@dataclass(frozen=True)
class SampleFiling:
    sample_id: int
    payload: str
    fragments: dict[str, str]


@dataclass(frozen=True)
class SchemaData:
    issuers: dict[str, Issuer]
    rules: dict[tuple[str, str], Rule]
    overrides: dict[tuple[str, str, str], Override]
    samples: dict[int, SampleFiling]

    def issuer(self, code: str) -> Issuer:
        return self.issuers[code]

    def rule(self, jurisdiction: str, txn_type: str) -> Rule:
        return self.rules[(jurisdiction, txn_type)]

    def override(self, issuer_code: str, jurisdiction: str, txn_type: str) -> Override | None:
        return self.overrides.get((issuer_code, jurisdiction, txn_type))

    def effective_threshold(
        self, issuer_code: str, jurisdiction: str, txn_type: str
    ) -> tuple[int, Rate, Rate]:
        override = self.override(issuer_code, jurisdiction, txn_type)
        if override is not None:
            return override.threshold_cents, override.cross_border_rate, override.retail_rate
        rule = self.rule(jurisdiction, txn_type)
        return rule.threshold_cents, rule.cross_border_rate, rule.retail_rate


def _values_block(sql: str, table: str) -> str:
    match = re.search(rf"INSERT INTO {table}.*?VALUES(.*?);", sql, re.DOTALL)
    if not match:
        raise ValueError(f"no INSERT INTO {table} found in schema")
    return match.group(1)


def load(path: str | Path = DEFAULT_SCHEMA_PATH) -> SchemaData:
    sql = Path(path).read_text()

    issuers: dict[str, Issuer] = {}
    for code, name, _entity_type, exempt_org in _ISSUER_ROW.findall(_values_block(sql, "issuers")):
        issuers[code] = Issuer(code=code, name=name, exempt=exempt_org != "0")

    rules: dict[tuple[str, str], Rule] = {}
    for jurisdiction, txn_type, threshold, cb_num, cb_den, rt_num, rt_den in _RULE_ROW.findall(
        _values_block(sql, "rule_thresholds")
    ):
        rules[(jurisdiction, txn_type)] = Rule(
            jurisdiction=jurisdiction,
            txn_type=txn_type,
            threshold_cents=int(threshold),
            cross_border_rate=Rate(int(cb_num), int(cb_den)),
            retail_rate=Rate(int(rt_num), int(rt_den)),
        )

    overrides: dict[tuple[str, str, str], Override] = {}
    for (
        issuer_code,
        jurisdiction,
        txn_type,
        threshold,
        cb_num,
        cb_den,
        rt_num,
        rt_den,
    ) in _OVERRIDE_ROW.findall(_values_block(sql, "issuer_rule_overrides")):
        overrides[(issuer_code, jurisdiction, txn_type)] = Override(
            issuer_code=issuer_code,
            jurisdiction=jurisdiction,
            txn_type=txn_type,
            threshold_cents=int(threshold),
            cross_border_rate=Rate(int(cb_num), int(cb_den)),
            retail_rate=Rate(int(rt_num), int(rt_den)),
        )

    payloads: dict[int, str] = {}
    for sample_id, encoded_payload, _note in _SAMPLE_FILING_ROW.findall(
        _values_block(sql, "sample_filings")
    ):
        payloads[int(sample_id)] = encoded_payload

    fragments_by_sample: dict[int, dict[str, str]] = {sid: {} for sid in payloads}
    for sample_id, json_key, json_value in _ACCEPTED_FRAGMENT_ROW.findall(
        _values_block(sql, "accepted_fragments")
    ):
        fragments_by_sample.setdefault(int(sample_id), {})[json_key] = json_value

    samples = {
        sid: SampleFiling(sample_id=sid, payload=payload, fragments=fragments_by_sample.get(sid, {}))
        for sid, payload in payloads.items()
    }

    return SchemaData(issuers=issuers, rules=rules, overrides=overrides, samples=samples)
