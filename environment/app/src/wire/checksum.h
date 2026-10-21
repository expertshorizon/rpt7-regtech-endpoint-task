#ifndef RPT7_CHECKSUM_H
#define RPT7_CHECKSUM_H

#include "../common/types.h"

int rpt7_checksum_of(const rpt7_fields_t *fields);
int rpt7_parse_checksum(const char *raw, int *out);

#endif
