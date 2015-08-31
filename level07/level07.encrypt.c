/*
export LIBRARY_PATH=/root/fusion/
gcc level07.encrypt.c -o level07.encrypt -lpak -m32 -ldl
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include "libpak.h"

void register_cmd(unsigned int opcode, unsigned int flags, void *(*fp)(void *))
{
	printf("reg\n");
}

void unregister_cmd(unsigned int opcode)
{
	printf("unreg\n");
}

struct ops regops = {
	.register_cmd = register_cmd,
	.unregister_cmd = unregister_cmd
};

int main()
{
	unsigned char *plaintext, *cipher;
  	int fd;
  	FILE *fd2;
  	struct stat statbuf;
  	unsigned int i, cipher_len;

  	fd = open("level07.unpak", O_RDONLY);
  	if(!fd) err(1, "Unable to open %s", "level07.unpak");
  	if(fstat(fd, &statbuf) == -1) 
		err(1, "Unable to fstat %s", "level07.unpak");

  	plaintext = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  	if(plaintext == MAP_FAILED) 
		err(1, "Unable to mmap %s", "level07.unpak");

	encrypt_pak(plaintext, statbuf.st_size, &cipher, &cipher_len);
	fd2 = fopen("level07.pak", "w+");
	fwrite(cipher, cipher_len, 1, fd2);
	fclose(fd2);
	for (i = 0; i<cipher_len; i++) printf("%02x:", cipher[i]);
	printf("\n");

	return 0;
}
