#include "checksum.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rpt7_checksum_of(const rpt7_fields_t *fields) {
    char canon[256];
    snprintf(canon, sizeof(canon), "%s,%s,%c,%ld,%s", fields->issuer_code,
             fields->jurisdiction, fields->txn_type, fields->amount_cents, fields->date8);
    unsigned long sum = 0;
    for (const char *p = canon; *p; p++) sum += (unsigned char)*p;
    return (int)(sum % 97);
}

int rpt7_parse_checksum(const char *raw, int *out) {
    size_t len = strlen(raw);
    if (len == 0 || len > 3) return -1;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)raw[i])) return -1;
    }
    char *endp = NULL;
    long v = strtol(raw, &endp, 10);
    if (endp == raw || *endp != '\0') return -1;
    if (v < 0 || v > 96) return -1;
    *out = (int)v;
    return 0;
}
