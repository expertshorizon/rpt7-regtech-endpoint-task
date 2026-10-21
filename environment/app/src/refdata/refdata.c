#include "refdata.h"

#include <sqlite3.h>
#include <string.h>

int rpt7_load_refdata(const char *db_path, rpt7_refdata_t *ref) {
    memset(ref, 0, sizeof(*ref));
    sqlite3 *db;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_stmt *stmt;
    const char *issuer_sql =
        "SELECT issuer_code, issuer_name, entity_type, exempt_org FROM issuers";
    if (sqlite3_prepare_v2(db, issuer_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->issuer_count < RPT7_MAX_ISSUERS) {
        rpt7_issuer_t *iss = &ref->issuers[ref->issuer_count++];
        strncpy(iss->issuer_code, (const char *)sqlite3_column_text(stmt, 0),
                sizeof(iss->issuer_code) - 1);
        strncpy(iss->issuer_name, (const char *)sqlite3_column_text(stmt, 1),
                sizeof(iss->issuer_name) - 1);
        strncpy(iss->entity_type, (const char *)sqlite3_column_text(stmt, 2),
                sizeof(iss->entity_type) - 1);
        iss->exempt_org = sqlite3_column_int(stmt, 3);
    }
    sqlite3_finalize(stmt);

    const char *rule_sql =
        "SELECT jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den FROM rule_thresholds";
    if (sqlite3_prepare_v2(db, rule_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->rule_count < RPT7_MAX_RULES) {
        rpt7_rule_t *rule = &ref->rules[ref->rule_count++];
        strncpy(rule->jurisdiction, (const char *)sqlite3_column_text(stmt, 0),
                sizeof(rule->jurisdiction) - 1);
        const char *tt = (const char *)sqlite3_column_text(stmt, 1);
        rule->txn_type = tt[0];
        rule->threshold_cents = sqlite3_column_int64(stmt, 2);
        rule->cross_border_multiplier =
            (double)sqlite3_column_int64(stmt, 3) / (double)sqlite3_column_int64(stmt, 4);
        rule->retail_multiplier =
            (double)sqlite3_column_int64(stmt, 5) / (double)sqlite3_column_int64(stmt, 6);
    }
    sqlite3_finalize(stmt);

    const char *override_sql =
        "SELECT issuer_code, jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den, effective_from "
        "FROM issuer_rule_overrides";
    if (sqlite3_prepare_v2(db, override_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->override_count < RPT7_MAX_OVERRIDES) {
        rpt7_override_t *ov = &ref->overrides[ref->override_count++];
        strncpy(ov->issuer_code, (const char *)sqlite3_column_text(stmt, 0),
                sizeof(ov->issuer_code) - 1);
        strncpy(ov->jurisdiction, (const char *)sqlite3_column_text(stmt, 1),
                sizeof(ov->jurisdiction) - 1);
        const char *tt = (const char *)sqlite3_column_text(stmt, 2);
        ov->txn_type = tt[0];
        ov->threshold_cents = sqlite3_column_int64(stmt, 3);
        ov->cross_border_multiplier =
            (double)sqlite3_column_int64(stmt, 4) / (double)sqlite3_column_int64(stmt, 5);
        ov->retail_multiplier =
            (double)sqlite3_column_int64(stmt, 6) / (double)sqlite3_column_int64(stmt, 7);
        strncpy(ov->effective_from, (const char *)sqlite3_column_text(stmt, 8),
                sizeof(ov->effective_from) - 1);
    }
    sqlite3_finalize(stmt);

    sqlite3_close(db);
    return 0;
}

const rpt7_issuer_t *rpt7_find_issuer(const rpt7_refdata_t *ref, const char *code) {
    for (int i = 0; i < ref->issuer_count; i++) {
        if (strcmp(ref->issuers[i].issuer_code, code) == 0) return &ref->issuers[i];
    }
    return NULL;
}

const rpt7_rule_t *rpt7_find_rule(const rpt7_refdata_t *ref, const char *jurisdiction,
                                   char txn_type) {
    for (int i = 0; i < ref->rule_count; i++) {
        if (ref->rules[i].txn_type == txn_type &&
            strcmp(ref->rules[i].jurisdiction, jurisdiction) == 0) {
            return &ref->rules[i];
        }
    }
    return NULL;
}

const rpt7_override_t *rpt7_find_override(const rpt7_refdata_t *ref, const char *issuer_code,
                                           const char *jurisdiction, char txn_type,
                                           const char *filing_date8) {
    (void)filing_date8;
    for (int i = 0; i < ref->override_count; i++) {
        const rpt7_override_t *ov = &ref->overrides[i];
        if (ov->txn_type != txn_type) continue;
        if (strcmp(ov->jurisdiction, jurisdiction) != 0) continue;
        if (strcmp(ov->issuer_code, issuer_code) == 0) return ov;
    }

    for (int i = 0; i < ref->override_count; i++) {
        const rpt7_override_t *ov = &ref->overrides[i];
        if (ov->txn_type == txn_type && strcmp(ov->jurisdiction, jurisdiction) == 0) return ov;
    }

    return NULL;
}
