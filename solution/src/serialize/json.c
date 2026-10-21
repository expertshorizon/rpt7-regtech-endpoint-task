#include "json.h"

#include <stdio.h>

static size_t json_escape_into(char *dst, size_t dstlen, const char *src) {
    size_t out = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && out + 1 < dstlen; p++) {
        unsigned char c = *p;
        const char *esc = NULL;
        switch (c) {
            case '"': esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n"; break;
            case '\r': esc = "\\r"; break;
            case '\t': esc = "\\t"; break;
            default: break;
        }
        if (esc) {
            size_t elen = 2;
            if (out + elen >= dstlen) break;
            dst[out++] = esc[0];
            dst[out++] = esc[1];
        } else if (c < 0x20) {
            if (out + 6 >= dstlen) break;
            out += (size_t)snprintf(dst + out, dstlen - out, "\\u%04x", c);
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
    return out;
}

void rpt7_to_json(const rpt7_decoded_t *d, char *buf, size_t buflen) {
    if (!d->ok) {
        snprintf(buf, buflen, "{\"error\":\"%s\"}", d->error);
        return;
    }
    char issuer_code[2 * sizeof(d->issuer_code) + 1];
    char issuer_name[2 * sizeof(d->issuer_name) + 1];
    char jurisdiction[2 * sizeof(d->jurisdiction) + 1];
    json_escape_into(issuer_code, sizeof(issuer_code), d->issuer_code);
    json_escape_into(issuer_name, sizeof(issuer_name), d->issuer_name);
    json_escape_into(jurisdiction, sizeof(jurisdiction), d->jurisdiction);
    snprintf(buf, buflen,
             "{"
             "\"issuer_code\":\"%s\","
             "\"issuer_name\":\"%s\","
             "\"jurisdiction\":\"%s\","
             "\"txn_type\":\"%c\","
             "\"amount_cents\":%ld,"
             "\"filing_date\":\"%s\","
             "\"exempt\":%s,"
             "\"retail\":%s,"
             "\"cross_border\":%s,"
             "\"manual_review\":%s,"
             "\"threshold_cents\":%ld,"
             "\"reportable\":%s"
             "}",
             issuer_code, issuer_name, jurisdiction, d->txn_type_code, d->amount_cents,
             d->filing_date, d->exempt ? "true" : "false", d->retail_flag ? "true" : "false",
             d->cross_border_flag ? "true" : "false", d->manual_review_flag ? "true" : "false",
             d->threshold_cents, d->reportable ? "true" : "false");
}
