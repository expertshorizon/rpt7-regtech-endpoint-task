#include "decision.h"

#include "../refdata/refdata.h"

static long apply_rate(long value, rpt7_rate_t rate) {
    if (rate.den == 0) return value;
    long product = value * rate.num;
    long quotient = product / rate.den;
    long remainder = product % rate.den;
    if (2 * remainder >= rate.den) quotient += 1;
    return quotient;
}

void rpt7_resolve_decision(const rpt7_refdata_t *ref, const rpt7_issuer_t *issuer,
                            const rpt7_rule_t *rule, const rpt7_fields_t *fields,
                            rpt7_decision_t *out) {
    int exempt_flag = fields->flags & 0x01;
    int retail_flag = (fields->flags >> 1) & 0x01;
    int cross_border_flag = (fields->flags >> 2) & 0x01;
    int manual_review_flag = (fields->flags >> 3) & 0x01;

    const rpt7_override_t *override = rpt7_find_override(
        ref, fields->issuer_code, fields->jurisdiction, fields->txn_type, fields->date8);
    long base_threshold = override ? override->threshold_cents : rule->threshold_cents;
    rpt7_rate_t cross_border_rate =
        override ? override->cross_border_rate : rule->cross_border_rate;
    rpt7_rate_t retail_rate = override ? override->retail_rate : rule->retail_rate;

    long effective_threshold = base_threshold;
    if (retail_flag) {
        effective_threshold = apply_rate(effective_threshold, retail_rate);
    }
    if (cross_border_flag) {
        effective_threshold = apply_rate(effective_threshold, cross_border_rate);
    }

    int exempt = issuer->exempt_org || exempt_flag;
    long abs_amount = fields->amount_cents < 0 ? -fields->amount_cents : fields->amount_cents;

    out->threshold_cents = effective_threshold;
    out->exempt = exempt;
    out->reportable = manual_review_flag || (!exempt && abs_amount >= effective_threshold);
}
