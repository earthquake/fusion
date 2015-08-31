/*
export LIBRARY_PATH=/root/fusion/
gcc level07.decrypt.c -o level07.decrypt -lpak -m32 -ldl
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
	unsigned char *ciphertext, *plaintext;
	int fd;
	FILE *fd2;
	struct stat statbuf;
	int status;
	unsigned int base, p_len, i;

	fd = open("level07.pak", O_RDONLY);
  	if(!fd) err(1, "Unable to open %s", "level07.pak");
  	if(fstat(fd, &statbuf) == -1) 
		err(1, "Unable to fstat %s", "level07.pak");

  	ciphertext = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  	if(ciphertext == MAP_FAILED) err(1, "Unable to mmap %s", "level07.pak");

	status = decrypt_pak(ciphertext, statbuf.st_size, &plaintext, &p_len);
	
	fd2 = fopen("level07.unpak", "w+");
	fwrite(plaintext, p_len, 1, fd2);
	fclose(fd2);


	for (i = 0; i<p_len; i++) printf("%02x:", plaintext[i]);
	printf("\n");
	return 0;
}
