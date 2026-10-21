#ifndef RPT7_JSON_H
#define RPT7_JSON_H

#include <stddef.h>

#include "../common/types.h"

void rpt7_to_json(const rpt7_decoded_t *d, char *buf, size_t buflen);

#endif
