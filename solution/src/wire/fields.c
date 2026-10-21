#include "fields.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim(char *s) {
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

static void to_upper(char *s) {
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

static int split_fields(char *payload, char *fields[], int max_fields) {
    int count = 0;
    char *tok = payload;
    for (;;) {
        char *comma = strchr(tok, ',');
        if (comma) *comma = '\0';
        if (count < max_fields) fields[count] = tok;
        count++;
        if (!comma) break;
        tok = comma + 1;
    }
    return count;
}

static int normalize_amount(const char *raw, long *out) {
    char buf[64];
    size_t len = strlen(raw);
    if (len == 0 || len >= sizeof(buf)) return -1;
    int negative = 0;
    size_t start = 0;
    size_t end = len;
    if (raw[0] == '(' && raw[len - 1] == ')') {
        negative = 1;
        start = 1;
        end = len - 1;
    }
    size_t j = 0;
    for (size_t i = start; i < end; i++) {
        char c = raw[i];
        if (c == '+') continue;
        if (c == '-') {
            negative = 1;
            continue;
        }
        if (!isdigit((unsigned char)c)) return -1;
        buf[j++] = c;
    }
    if (j == 0) return -1;
    buf[j] = '\0';
    char *endp = NULL;
    long val = strtol(buf, &endp, 10);
    if (endp == buf || *endp != '\0') return -1;
    *out = negative ? -val : val;
    return 0;
}

static int normalize_date(const char *raw, char *out8) {
    char digits[16];
    size_t j = 0;
    for (const char *p = raw; *p; p++) {
        if (isdigit((unsigned char)*p)) {
            if (j >= sizeof(digits) - 1) return -1;
            digits[j++] = *p;
        } else if (*p == '-' || *p == '/') {
            continue;
        } else {
            return -1;
        }
    }
    digits[j] = '\0';
    if (j != 8) return -1;
    memcpy(out8, digits, 9);
    return 0;
}

static int normalize_flags(const char *raw, int *out) {
    if (strlen(raw) != 2) return -1;
    for (int i = 0; i < 2; i++) {
        if (!isxdigit((unsigned char)raw[i])) return -1;
    }
    char *endp = NULL;
    long v = strtol(raw, &endp, 16);
    if (endp == raw || *endp != '\0') return -1;
    if (v & ~0x0F) return -1;
    *out = (int)v;
    return 0;
}

int rpt7_parse_fields(char *payload, rpt7_fields_t *out, char *error, size_t error_len) {
    char *fields[8];
    int n = split_fields(payload, fields, 8);
    if (n != 8) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }
    for (int i = 0; i < 8; i++) trim(fields[i]);

    char magic[16];
    strncpy(magic, fields[0], sizeof(magic) - 1);
    magic[sizeof(magic) - 1] = '\0';
    to_upper(magic);
    if (strcmp(magic, "RPT7") != 0) {
        snprintf(error, error_len, "bad_magic");
        return -1;
    }

    memset(out, 0, sizeof(*out));

    strncpy(out->issuer_code, fields[1], sizeof(out->issuer_code) - 1);
    to_upper(out->issuer_code);
    if (strlen(out->issuer_code) == 0) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }

    strncpy(out->jurisdiction, fields[2], sizeof(out->jurisdiction) - 1);
    to_upper(out->jurisdiction);

    if (strlen(fields[3]) != 1) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }
    out->txn_type = (char)toupper((unsigned char)fields[3][0]);

    if (normalize_amount(fields[4], &out->amount_cents) != 0) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }

    if (normalize_date(fields[5], out->date8) != 0) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }

    if (normalize_flags(fields[6], &out->flags) != 0) {
        snprintf(error, error_len, "malformed_payload");
        return -1;
    }

    strncpy(out->checksum_raw, fields[7], sizeof(out->checksum_raw) - 1);

    return 0;
}
