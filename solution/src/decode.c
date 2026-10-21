#include "decode.h"

#include <stdio.h>
#include <string.h>

#include "compliance/decision.h"
#include "refdata/refdata.h"
#include "wire/checksum.h"
#include "wire/fields.h"

void rpt7_decode(const rpt7_refdata_t *ref, const char *payload_in, rpt7_decoded_t *out) {
    memset(out, 0, sizeof(*out));
    char payload[512];
    strncpy(payload, payload_in, sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    rpt7_fields_t fields;
    if (rpt7_parse_fields(payload, &fields, out->error, sizeof(out->error)) != 0) {
        out->ok = 0;
        return;
    }

    int checksum_claimed;
    if (rpt7_parse_checksum(fields.checksum_raw, &checksum_claimed) != 0) {
        out->ok = 0;
        snprintf(out->error, sizeof(out->error), "malformed_payload");
        return;
    }

    if (rpt7_checksum_of(&fields) != checksum_claimed) {
        out->ok = 0;
        snprintf(out->error, sizeof(out->error), "checksum_mismatch");
        return;
    }

    const rpt7_issuer_t *issuer = rpt7_find_issuer(ref, fields.issuer_code);
    if (!issuer) {
        out->ok = 0;
        snprintf(out->error, sizeof(out->error), "unknown_issuer");
        return;
    }

    const rpt7_rule_t *rule = rpt7_find_rule(ref, fields.jurisdiction, fields.txn_type);
    if (!rule) {
        out->ok = 0;
        snprintf(out->error, sizeof(out->error), "unknown_jurisdiction_or_type");
        return;
    }

    rpt7_decision_t decision;
    rpt7_resolve_decision(ref, issuer, rule, &fields, &decision);

    out->ok = 1;
    strncpy(out->issuer_code, fields.issuer_code, sizeof(out->issuer_code) - 1);
    strncpy(out->issuer_name, issuer->issuer_name, sizeof(out->issuer_name) - 1);
    strncpy(out->jurisdiction, fields.jurisdiction, sizeof(out->jurisdiction) - 1);
    out->txn_type_code = fields.txn_type;
    out->amount_cents = fields.amount_cents;
    snprintf(out->filing_date, sizeof(out->filing_date), "%.4s-%.2s-%.2s", fields.date8,
             fields.date8 + 4, fields.date8 + 6);
    out->exempt_flag = fields.flags & 0x01;
    out->retail_flag = (fields.flags >> 1) & 0x01;
    out->cross_border_flag = (fields.flags >> 2) & 0x01;
    out->manual_review_flag = (fields.flags >> 3) & 0x01;
    out->threshold_cents = decision.threshold_cents;
    out->exempt = decision.exempt;
    out->reportable = decision.reportable;
}
