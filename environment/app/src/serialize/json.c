#include "json.h"

#include <stdio.h>

void rpt7_to_json(const rpt7_decoded_t *d, char *buf, size_t buflen) {
    if (!d->ok) {
        snprintf(buf, buflen, "{\"error\":\"%s\"}", d->error);
        return;
    }
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
             d->issuer_code, d->issuer_name, d->jurisdiction, d->txn_type_code, d->amount_cents,
             d->filing_date, d->exempt ? "true" : "false", d->retail_flag ? "true" : "false",
             d->cross_border_flag ? "true" : "false", d->manual_review_flag ? "true" : "false",
             d->threshold_cents, d->reportable ? "true" : "false");
}
