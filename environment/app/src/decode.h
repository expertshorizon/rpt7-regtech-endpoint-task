#ifndef RPT7_DECODE_H
#define RPT7_DECODE_H

#include "common/types.h"

void rpt7_decode(const rpt7_refdata_t *ref, const char *payload_in, rpt7_decoded_t *out);

#endif
