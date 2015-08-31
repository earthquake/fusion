#level07 solution

I have spent a few days/weeks to solve this, but finally have it, reliably.<br />
In a few sentences here are some thoughts:<br />
<br />
level07 binary registers two functions into a linked list and both of them could have called with a special prefix (the opcode of the function). But after loading and calling the libpak.so, it is going to read up the default .pak file which removes the second registered function (execute_command), so the easy way to execute code is gone by default.<br />
By reversing the libpak.so, I managed to understand the way how the binary works:<br />
- load_new_pakfile can be invoked by an UDP packet previously explained<br />
- it connects back to us for the pak file encoded<br />
- encoding is easy, explained by the source<br />
- encrypted pak is sent and decoded, and will be decrypted by the libpak with rc4<br />
- easy to "implement" encryption/decryption by using libpak.so and invoking the functions<br />
- after decryption, the run_pak_vm runs on the decrypted pak which is a DFA (Deterministic Finite Automata)<br />
<br />
The automata can do the following things:<br />
- write any 4bytes into a variable on stack<br />
- write arbitrary message into a variable that is allocated on the fly on the heap<br />
- substract/add two 4bytes values - this is f*cked up this is why I wasted a hell of a lot of time, loop should be decremented only by one<br />
- writing NULL into a variable on stack<br />
- call dlopen() on a file (this was the solution btw)<br />
- call dlsym() on any object<br />
- loop the variables<br />
- unregister an opcode (this is done by the default pak file/on execute_command function)<br />
- write data into a file from a memory address<br />
- write any 4 bytes into any memory address (seems nice, isn't it?)<br />
<br />
I wrote multiple python scripts and c codes to solve this level:<br />
- level07.client.py - asks the server to connect back to us and/or send any udp packet with the opcode and arguments<br />
- level07.server.py - listens on the specified port and wait for incoming connection to serve the level07.pak file encoded<br />
- level07.decrypt.c - decrypt any well-formed and ecrypted pak file (level07.pak)<br />
- level07.encrypt.c - encrypt any decrypted pak file (level07.unpak)<br />
- level07.makepak.py - DFA implemented in python, works as a "library", you can craft your on "commands"<br />
- level07.makepak.final.py - actual exploit<br />
- level07.so.c - shared object c file<br />
<br />
How I tried:<br />
First I tried to resolve a function address to have a fix address and later to substract the difference which is constant, but because of the substraction was not implemented properly (maybe on purpose) I could not solve this problem, to find a reliable way to gain knowledge about the base address.<br />
Then I tried to find some kind of info leak that can be accessed from the attacker machine, but no luck. Without the info leak I had no prior knowledge about the addresses. With the knowledge I would have been able to resolve the cmdtab_head object on the heap, allocate a new heap variable, craft a partly valid linked-list and just replace the pointer on the resolved address to the newly allocated address. When I cheated, this worked and I managed to replace the linked list with the one that points to the execute_command() function. But because I had no luck with the infoleak, I did not manage to write an exploit that is reliable.<br />
<br />
How I solved:<br />
When I first saw the dlopen function, I had a feeling maybe I can write out an .so and have some kind of constructor in it, but I didn't tried because I thought I need to find a stack overflow (based on the sheet of the level). Finally I created a shared object that has an initialization function that is called when the object is loaded. This way I managed to create a pak file that stores the filename on heap, the content of the .so file on heap and writes into a file. After that we only need to call dlopen() in the DFA and there it is, our code is running on the victim machine. Piece of cake, huh? It wasn't :)<br />
<br />
