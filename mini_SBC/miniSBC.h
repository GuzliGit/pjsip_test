#ifndef MINISBC_H
#define MINISBC_H

#include <pjlib.h>

#define MAX_ADDR_LEN 32
#define ENDPOINT_NAME "siptest"

int start_sbc(pj_sockaddr*, pj_sockaddr*);

#endif