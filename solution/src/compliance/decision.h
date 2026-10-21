#ifndef RPT7_DECISION_H
#define RPT7_DECISION_H

#include "../common/types.h"

typedef struct {
    long threshold_cents;
    int exempt;
    int reportable;
} rpt7_decision_t;

void rpt7_resolve_decision(const rpt7_refdata_t *ref, const rpt7_issuer_t *issuer,
                            const rpt7_rule_t *rule, const rpt7_fields_t *fields,
                            rpt7_decision_t *out);

#endif
