#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
        // just paste your filter here
        char *filters = " \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\r\x01\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00";

        unsigned short num_insns = 5; // just count the number of instructions, we dont care.

        printf("%hu\n", num_insns);
        for (unsigned short i = 0; i < num_insns; i++) {
                printf("%04hx %02hhx %02hhx %08x\n",
                       ((struct sock_filter*)filters)[i].code,
                       ((struct sock_filter*)filters)[i].jt,
                       ((struct sock_filter*)filters)[i].jf,
                       ((struct sock_filter*)filters)[i].k);
        }

        return 0;
}
