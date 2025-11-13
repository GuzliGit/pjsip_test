#include "miniSBC.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("USAGE: ./miniSBC <internal_addr> <outer_addr>\n");
        return -1;
    }
    if (strlen(argv[1]) > MAX_ADDR_LEN || strlen(argv[2]) > MAX_ADDR_LEN)
    {
        printf("ADDRESS LEN IS TOO LONG\n");
        return -1;
    }

    pj_sockaddr* in_addr = malloc(sizeof(pj_sockaddr));
    pj_sockaddr* out_addr = malloc(sizeof(pj_sockaddr));

    pj_str_t inaddr_str = pj_str(argv[1]);
    if (pj_sockaddr_parse(PJ_AF_INET, 0, &inaddr_str, in_addr) != PJ_SUCCESS)
    {
        printf("CAN'T PARSE INTERNAL ADDRESS\n");
        goto error;
    }
    pj_str_t outaddr_str = pj_str(argv[2]);
    if (pj_sockaddr_parse(PJ_AF_INET, 0, &outaddr_str, out_addr) != PJ_SUCCESS)
    {
        printf("CANT'T PARSE OUTER ADDRESS\n");
        goto error;
    }

    start_sbc(in_addr, out_addr);
    free(in_addr);
    free(out_addr);

    return 0;

error:
    if (in_addr)
        free(in_addr);
    if (out_addr)
        free(out_addr);
    
    return -1;
}