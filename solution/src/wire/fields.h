#ifndef RPT7_FIELDS_H
#define RPT7_FIELDS_H

#include <stddef.h>

#include "../common/types.h"

int rpt7_parse_fields(char *payload, rpt7_fields_t *out, char *error, size_t error_len);

#endif
