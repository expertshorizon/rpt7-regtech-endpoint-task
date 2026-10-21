#ifndef RPT7_REFDATA_H
#define RPT7_REFDATA_H

#include "../common/types.h"

int rpt7_load_refdata(const char *db_path, rpt7_refdata_t *ref);
const rpt7_issuer_t *rpt7_find_issuer(const rpt7_refdata_t *ref, const char *code);
const rpt7_rule_t *rpt7_find_rule(const rpt7_refdata_t *ref, const char *jurisdiction,
                                   char txn_type);
const rpt7_override_t *rpt7_find_override(const rpt7_refdata_t *ref, const char *issuer_code,
                                           const char *jurisdiction, char txn_type,
                                           const char *filing_date8);

#endif
