#ifndef MINISBC_H
#define MINISBC_H

#include <pjlib.h>

#define MEDIA_POOL_SIZE 512

#define MAX_ADDR_LEN 32
#define MAX_SLOTS 8

#define ENDPOINT_NAME "siptest"
#define RTP_PORT 5000

int start_sbc(pj_sockaddr*, pj_sockaddr*);

#endif