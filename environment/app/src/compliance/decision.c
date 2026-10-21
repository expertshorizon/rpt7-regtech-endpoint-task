#include "decision.h"

#include "../refdata/refdata.h"

void rpt7_resolve_decision(const rpt7_refdata_t *ref, const rpt7_issuer_t *issuer,
                            const rpt7_rule_t *rule, const rpt7_fields_t *fields,
                            rpt7_decision_t *out) {
    int exempt_flag = fields->flags & 0x01;
    int cross_border_flag = (fields->flags >> 2) & 0x01;

    const rpt7_override_t *override = rpt7_find_override(
        ref, fields->issuer_code, fields->jurisdiction, fields->txn_type, fields->date8);
    long base_threshold = override ? override->threshold_cents : rule->threshold_cents;
    double multiplier = rule->cross_border_multiplier;

    long effective_threshold = base_threshold;
    if (cross_border_flag) {
        effective_threshold = (long)(base_threshold * multiplier);
    }

    int exempt = issuer->exempt_org && exempt_flag;
    long abs_amount = fields->amount_cents < 0 ? -fields->amount_cents : fields->amount_cents;

    out->threshold_cents = effective_threshold;
    out->exempt = exempt;
    out->reportable = !exempt && abs_amount > effective_threshold;
}
