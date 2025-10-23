#include "answerphone.h"
#include <stdio.h>
#include <string.h>

int is_correct_len(size_t user_len, size_t domain_len)
{
    return (user_len > 0 && user_len < MAX_USERNAME_LEN && domain_len > 0 && domain_len < MAX_DOMAIN_LEN); 
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("USAGE: ./answerphone <SIP_USER> <SIP_DOMAIN>\n");
        return -1;
    }

    size_t user_len = strlen(argv[1]);
    size_t domain_len = strlen(argv[2]);
    if (!is_correct_len(user_len, domain_len))
    {
        printf("Incorrect SIP_USER or SIP_DOMAIN, the max length is %d(for SIP_USER) | %d(for SIP_DOMAIN)!\n", MAX_USERNAME_LEN, MAX_DOMAIN_LEN);
        return -1;
    }

    if (start_answerphone(argv[1], argv[2]) != 0)
    {
        return -1;
    }

    return 0;
}