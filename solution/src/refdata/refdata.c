#include "refdata.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

static void to_upper_inplace(char *s) {
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

static int cmp_issuer(const void *a, const void *b) {
    const rpt7_issuer_t *x = (const rpt7_issuer_t *)a;
    const rpt7_issuer_t *y = (const rpt7_issuer_t *)b;
    return strcmp(x->issuer_code, y->issuer_code);
}

static int cmp_rule(const void *a, const void *b) {
    const rpt7_rule_t *x = (const rpt7_rule_t *)a;
    const rpt7_rule_t *y = (const rpt7_rule_t *)b;
    int c = strcmp(x->jurisdiction, y->jurisdiction);
    if (c != 0) return c;
    return (int)(unsigned char)x->txn_type - (int)(unsigned char)y->txn_type;
}

static int cmp_override(const void *a, const void *b) {
    const rpt7_override_t *x = (const rpt7_override_t *)a;
    const rpt7_override_t *y = (const rpt7_override_t *)b;
    int c = strcmp(x->issuer_code, y->issuer_code);
    if (c != 0) return c;
    c = strcmp(x->jurisdiction, y->jurisdiction);
    if (c != 0) return c;
    c = (int)(unsigned char)x->txn_type - (int)(unsigned char)y->txn_type;
    if (c != 0) return c;
    return strcmp(x->effective_from, y->effective_from);
}

static int override_key_cmp(const rpt7_override_t *row, const char *issuer_code,
                             const char *jurisdiction, char txn_type,
                             const char *filing_date8) {
    int c = strcmp(row->issuer_code, issuer_code);
    if (c != 0) return c;
    c = strcmp(row->jurisdiction, jurisdiction);
    if (c != 0) return c;
    c = (int)(unsigned char)row->txn_type - (int)(unsigned char)txn_type;
    if (c != 0) return c;
    return strcmp(row->effective_from, filing_date8);
}

static int count_rows(sqlite3 *db, const char *sql) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static void copy_text(char *dst, size_t dstlen, const unsigned char *src) {
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen((const char *)src);
    if (n > dstlen - 1) n = dstlen - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void rpt7_free_refdata(rpt7_refdata_t *ref) {
    free(ref->issuers);
    free(ref->rules);
    free(ref->overrides);
    memset(ref, 0, sizeof(*ref));
}

int rpt7_load_refdata(const char *db_path, rpt7_refdata_t *ref) {
    memset(ref, 0, sizeof(*ref));
    sqlite3 *db;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    int issuer_total = count_rows(db, "SELECT COUNT(*) FROM issuers");
    int rule_total = count_rows(db, "SELECT COUNT(*) FROM rule_thresholds");
    int override_total = count_rows(db, "SELECT COUNT(*) FROM issuer_rule_overrides");
    if (issuer_total < 0 || rule_total < 0 || override_total < 0) {
        sqlite3_close(db);
        return -1;
    }

    ref->issuers = issuer_total > 0 ? calloc((size_t)issuer_total, sizeof(rpt7_issuer_t)) : NULL;
    ref->rules = rule_total > 0 ? calloc((size_t)rule_total, sizeof(rpt7_rule_t)) : NULL;
    ref->overrides =
        override_total > 0 ? calloc((size_t)override_total, sizeof(rpt7_override_t)) : NULL;
    if ((issuer_total > 0 && !ref->issuers) || (rule_total > 0 && !ref->rules) ||
        (override_total > 0 && !ref->overrides)) {
        rpt7_free_refdata(ref);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_stmt *stmt;
    const char *issuer_sql =
        "SELECT issuer_code, issuer_name, entity_type, exempt_org FROM issuers";
    if (sqlite3_prepare_v2(db, issuer_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rpt7_free_refdata(ref);
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->issuer_count < issuer_total) {
        rpt7_issuer_t *iss = &ref->issuers[ref->issuer_count++];
        copy_text(iss->issuer_code, sizeof(iss->issuer_code), sqlite3_column_text(stmt, 0));
        to_upper_inplace(iss->issuer_code);
        copy_text(iss->issuer_name, sizeof(iss->issuer_name), sqlite3_column_text(stmt, 1));
        copy_text(iss->entity_type, sizeof(iss->entity_type), sqlite3_column_text(stmt, 2));
        iss->exempt_org = sqlite3_column_int(stmt, 3);
    }
    sqlite3_finalize(stmt);

    const char *rule_sql =
        "SELECT jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den FROM rule_thresholds";
    if (sqlite3_prepare_v2(db, rule_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rpt7_free_refdata(ref);
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->rule_count < rule_total) {
        rpt7_rule_t *rule = &ref->rules[ref->rule_count++];
        copy_text(rule->jurisdiction, sizeof(rule->jurisdiction), sqlite3_column_text(stmt, 0));
        to_upper_inplace(rule->jurisdiction);
        const unsigned char *tt = sqlite3_column_text(stmt, 1);
        rule->txn_type = tt ? (char)toupper(tt[0]) : '\0';
        rule->threshold_cents = (long)sqlite3_column_int64(stmt, 2);
        rule->cross_border_rate.num = (long)sqlite3_column_int64(stmt, 3);
        rule->cross_border_rate.den = (long)sqlite3_column_int64(stmt, 4);
        rule->retail_rate.num = (long)sqlite3_column_int64(stmt, 5);
        rule->retail_rate.den = (long)sqlite3_column_int64(stmt, 6);
    }
    sqlite3_finalize(stmt);

    const char *override_sql =
        "SELECT issuer_code, jurisdiction, txn_type, threshold_cents, cross_border_rate_num, "
        "cross_border_rate_den, retail_rate_num, retail_rate_den, effective_from "
        "FROM issuer_rule_overrides";
    if (sqlite3_prepare_v2(db, override_sql, -1, &stmt, NULL) != SQLITE_OK) {
        rpt7_free_refdata(ref);
        sqlite3_close(db);
        return -1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && ref->override_count < override_total) {
        rpt7_override_t *ov = &ref->overrides[ref->override_count++];
        copy_text(ov->issuer_code, sizeof(ov->issuer_code), sqlite3_column_text(stmt, 0));
        to_upper_inplace(ov->issuer_code);
        copy_text(ov->jurisdiction, sizeof(ov->jurisdiction), sqlite3_column_text(stmt, 1));
        to_upper_inplace(ov->jurisdiction);
        const unsigned char *tt = sqlite3_column_text(stmt, 2);
        ov->txn_type = tt ? (char)toupper(tt[0]) : '\0';
        ov->threshold_cents = (long)sqlite3_column_int64(stmt, 3);
        ov->cross_border_rate.num = (long)sqlite3_column_int64(stmt, 4);
        ov->cross_border_rate.den = (long)sqlite3_column_int64(stmt, 5);
        ov->retail_rate.num = (long)sqlite3_column_int64(stmt, 6);
        ov->retail_rate.den = (long)sqlite3_column_int64(stmt, 7);
        copy_text(ov->effective_from, sizeof(ov->effective_from), sqlite3_column_text(stmt, 8));
    }
    sqlite3_finalize(stmt);

    sqlite3_close(db);

    if (ref->issuer_count > 1) {
        qsort(ref->issuers, (size_t)ref->issuer_count, sizeof(rpt7_issuer_t), cmp_issuer);
    }
    if (ref->rule_count > 1) {
        qsort(ref->rules, (size_t)ref->rule_count, sizeof(rpt7_rule_t), cmp_rule);
    }
    if (ref->override_count > 1) {
        qsort(ref->overrides, (size_t)ref->override_count, sizeof(rpt7_override_t), cmp_override);
    }
    return 0;
}

const rpt7_issuer_t *rpt7_find_issuer(const rpt7_refdata_t *ref, const char *code) {
    if (ref->issuer_count <= 0) return NULL;
    rpt7_issuer_t key;
    memset(&key, 0, sizeof(key));
    copy_text(key.issuer_code, sizeof(key.issuer_code), (const unsigned char *)code);
    return (const rpt7_issuer_t *)bsearch(&key, ref->issuers, (size_t)ref->issuer_count,
                                          sizeof(rpt7_issuer_t), cmp_issuer);
}

const rpt7_rule_t *rpt7_find_rule(const rpt7_refdata_t *ref, const char *jurisdiction,
                                   char txn_type) {
    if (ref->rule_count <= 0) return NULL;
    rpt7_rule_t key;
    memset(&key, 0, sizeof(key));
    copy_text(key.jurisdiction, sizeof(key.jurisdiction), (const unsigned char *)jurisdiction);
    key.txn_type = txn_type;
    return (const rpt7_rule_t *)bsearch(&key, ref->rules, (size_t)ref->rule_count,
                                        sizeof(rpt7_rule_t), cmp_rule);
}

const rpt7_override_t *rpt7_find_override(const rpt7_refdata_t *ref, const char *issuer_code,
                                           const char *jurisdiction, char txn_type,
                                           const char *filing_date8) {
    if (ref->override_count <= 0) return NULL;
    int lo = 0;
    int hi = ref->override_count - 1;
    int floor_index = -1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (override_key_cmp(&ref->overrides[mid], issuer_code, jurisdiction, txn_type,
                              filing_date8) <= 0) {
            floor_index = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    if (floor_index < 0) return NULL;
    const rpt7_override_t *candidate = &ref->overrides[floor_index];
    if (strcmp(candidate->issuer_code, issuer_code) != 0) return NULL;
    if (strcmp(candidate->jurisdiction, jurisdiction) != 0) return NULL;
    if (candidate->txn_type != txn_type) return NULL;
    return candidate;
}
