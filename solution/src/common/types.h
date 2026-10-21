#ifndef RPT7_TYPES_H
#define RPT7_TYPES_H

typedef struct {
    char issuer_code[16];
    char issuer_name[128];
    char entity_type[32];
    int exempt_org;
} rpt7_issuer_t;

typedef struct {
    long num;
    long den;
} rpt7_rate_t;

typedef struct {
    char jurisdiction[8];
    char txn_type;
    long threshold_cents;
    rpt7_rate_t cross_border_rate;
    rpt7_rate_t retail_rate;
} rpt7_rule_t;

typedef struct {
    char issuer_code[16];
    char jurisdiction[8];
    char txn_type;
    long threshold_cents;
    rpt7_rate_t cross_border_rate;
    rpt7_rate_t retail_rate;
    char effective_from[16];
} rpt7_override_t;

typedef struct {
    rpt7_issuer_t *issuers;
    int issuer_count;
    rpt7_rule_t *rules;
    int rule_count;
    rpt7_override_t *overrides;
    int override_count;
} rpt7_refdata_t;

typedef struct {
    char issuer_code[16];
    char jurisdiction[8];
    char txn_type;
    long amount_cents;
    char date8[16];
    int flags;
    char checksum_raw[8];
} rpt7_fields_t;

typedef struct {
    int ok;
    char error[64];

    char issuer_code[16];
    char issuer_name[128];
    char jurisdiction[8];
    char txn_type_code;
    long amount_cents;
    char filing_date[16];
    int exempt_flag;
    int retail_flag;
    int cross_border_flag;
    int manual_review_flag;
    long threshold_cents;
    int exempt;
    int reportable;
} rpt7_decoded_t;

#endif
