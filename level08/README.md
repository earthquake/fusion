# level08
Again a few months have passed to solve? this level. Wasn't easy, but it looks like that now. I can't say I solved in full, because there is still some things to do, but I don't know how to do it. Epic fail, really. Last part would be to break out from the chroot, but I can't. I spent enormous time to do research on chroot escapes, wrote a tool and still can't get out of it :) In case you manage solve it, please drop me a mail.

## Source code

The source is the usual, we do not have access to everything some functions are "made-up" (source codes are not published), but still understandable. The binary starts and binds on the port tcp/20008 as usual and listens. When a client connects then it spawns a new process (same process but with *--client* arg) by calling *execve()*. This is important from exploiting POV, because it uses *execve()* and not *fork()*, a fully new process will be started. *fork()* copies the memory and give the execution to the process. By the *fork* way the stack canary will be the same and if there is a possibility (which is there in this scenario), then we can bruteforce the canaries. But because of the *execve()*, we can't do that unfortunately, which was a big bottleneck for me at the moment.  
Furthermore whe the process is restarted calls *chroot()* and *chdir()* into the */home/level08* directory and drops all the privileges, even the effective and saved uid/gid. This means we have to break out from chroot with an unprivileged user. Based on my research you can only do that in two scenarios:
- ptrace: a non-chrooted process exists on the system with the same uid and ptrace can be used
- move-out-of-chroot: other chrooted process moves out your cwd from the chroot of the process.

None of the above scenarios will work for you. There is no other process which isn't chrooted or chrooted into another directory. * I scratched my head at this point for a few weeks again *

## Encryption

After the initialization phase the spawned process will handle your requests. The communication is encrypted with NaCl (Networking and Cryptography library) which has asymmetric (public-key) encryption routins that are used here. I try to stick to python, which isn't always the best idea. As it turned out that python has two nacl library/wrapper that could be used. Unfortunately the pynacl wasn't working the same way as the c library, gave different results for me, so I changed to pysodium wrapper. Big up Stef!  
Life isn't just that easy. Probably something have changed in libsodium, but pysodium wasn't working right away. As far as I remember it looked for a symbol in the library which doesn't exist anymore, furtunately it was an easy fix.  
Then I wrote some c and python code to match up with the binary and figured it slowly (Yepp I'm slow sometimes I just mixing up things which make no sense after things are fixed, but who doesn't?). You can find my ugly c tests in the repo.

## Usage

After connecting to the server it will send you it's public key. You generate one key pair and send your public key to the server. Encryption and decyption will be done with these keys. After the key exchange you can send arbitrary data, encrypted data will land in the decryption queue, then the process queue will process it and an output will be generated. The output will land in the ecryption queue and after encryption it will be sent to you. That's what the code does.  
The most important part for us the process queue/pool which handles our input. It does either of the following:
- *m0777name* - creates a directory with the name *"name"* and mode *0777*
- *o0777name* - opens *(O_CREAT|O_TRUNC|O_WRONLY)* file named *"name"* with mode *0777* and outputs the number of the file descriptor
- *w7,0DATA* - writes *"DATA"* to the fd *7* from offset *0*
- *c7* - closes fd *7

Okay, we can write files on the server under the /home/level08 (because of the chroot) and create directories, but how do we execute code?

## Exploitation

The website states this is a stack overflow, but after *level07* nobody can be sure about that, right? After my script was working properly I tried to find the vulnerable part. The macro *set_str_buffer* looked really nasty first (because of the *strcpy()*) but unfortunately all  inputs are hardcoded.  
I found two ways to corrput the stack, first is based on the hints that can be found in *decryption_worker()* - threads are not locked properly, could mean (and means) some corruption for us.  
The other one which is more reliable and nice is the *sanity_check_name()*. It has a fixed size buffer called buf and we can overflow that with the *realpath()* function. It is really easy and trivial to do, so we could be pleased until we realize that the binary was compiled with SSP, so we have a stack canary that protects the stack:  
> stack smashing detected ***: /opt/fusion/bin/level08 terminated

Already explained in the beginning what is the problem with our canary. It is generated randomly, we cannot bruteforce it (you can, but the probability that you will find the correct one is almost zero). I have spent a few weeks on research of stack canaries and bypass techniques and found nothing that is useful here.

## Hints

This is the point where you should forget about your bottleneck and find other ways to exploit the vulnerability. I read thru the source code but found nothing, then in a clear moment I noticed something strange. I previously saw that there is a *lib/i386-linux-gnu/* directory which has some kind of shared library, but I thought that is only there for help in case you have RCE and then you can load it and reuse the already compiled functions. I made a huge mistake here, even the name was telling. If you decompile the *.so*, you will find that the *_init* function writes out the **"evil.so loaded"** message, which is a hint indeed. Unfortunately I have terminated the connection before read out this message from the channel, I never saw this previously.  
When a stack corruption happens and the OS notices it terminates the program with **"stack smashing detected \*\*\*"** message. After that message an awful lot of code runs including the *_Unwind_Backtrace()* which provides the stacktrace to the user for debugging purposes. This function resides in the *libgcc_s.so* and because the program runs in a chrooted environment the *libgcc_s.so.1* will be loaded with the evil init function. The shared library is writeable for us which means we can execute any code within the environment.  
Stack overflow exploitation without writing code to the stack, nice huh? There is no need to know the canary this way.

## Steps summarized

1. implement encryption and decryption routins
2. open the lib/i386-linux-gnu/libgcc_s.so.1 file
3. overwrite with your shared library (_init function will be executed)
4. close the file decriptor
5. create a directory - trigger overflow
6. init function runs

## Chroot

We can execute any code in the chrooted environment, even spawn a shell, but what's the point? We are still enclosed with our unprivileged user. Based on the previous levels there was no requirement to gain root, so I doubt that would be the next step. My solution would had been to create a .ssh directory (which is forbidden in the binary, I thought it is a hint as well) and upload my pub key into the authorized_keys file and log in thru ssh. This approach doesn't work, because our user (*level08*) isn't in the passwd file unfortunately, so sshd doesn't let us in. I have no other ideas hwo to break out. If you do please drop me a mail, I really excited to see how others solve this challange.

Twitter: @xoreipeip



