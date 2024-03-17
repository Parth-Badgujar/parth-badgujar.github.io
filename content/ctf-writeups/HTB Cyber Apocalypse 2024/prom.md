---
linkTitle: The PROM
title: Hardware - The PROM 
type: docs
---

* Difficulty : Medium 
* Description : After entering the door, you navigate through the building, evading guards, and quickly locate the server room in the basement. Despite easy bypassing of security measures and cameras, laser motion sensors pose a challenge. They're controlled by a small 8-bit computer equipped with AT28C16 a well-known EEPROM as its control unit. Can you uncover the EEPROM's secrets?

## Initial Recon 

* We were given an address and a port of a remote server to communicate but no distributables. 
* As you connect to the IP using netcat, you get this interface : 

```
      AT28C16 EEPROMs
       _____   _____
      |     \_/     |
A7   [| 1        24 |] VCC
A6   [| 2        23 |] A8
A5   [| 3        22 |] A9
A4   [| 4        21 |] !WE
A3   [| 5        20 |] !OE
A2   [| 6        19 |] A10
A1   [| 7        18 |] !CE
A0   [| 8        17 |] I/O7
I/O0 [| 9        16 |] I/O6
I/O1 [| 10       15 |] I/O5
I/O2 [| 11       14 |] I/O4
GND  [| 12       13 |] I/O3
      |_____________|

> help

Usage:
  method_name(argument)

EEPROM COMMANDS:
  set_address_pins(address)  Sets the address pins from A10 to A0 to the specified values.
  set_ce_pin(volts)          Sets the CE (Chip Enable) pin voltage to the specified value.
  set_oe_pin(volts)          Sets the OE (Output Enable) pin voltage to the specified value.
  set_we_pin(volts)          Sets the WE (Write Enable) pin voltage to the specified value.
  set_io_pins(data)          Sets the I/O (Input/Output) pins to the specified data values.
  read_byte()                Reads a byte from the memory at the current address.
  write_byte()               Writes the current data to the memory at the current address.
  help                       Displays this help menu.

Examples:
  set_ce_pin(3.5)
  set_io_pins([0, 5.1, 3, 0, 0, 3.1, 2, 4.2])

>
```  

* So we can basically control the voltage levels using the following commands and somehow get the flag out of it. 
* Offcourse we cannot directly read the memory, we'll first have to configure it to allow us to read bytes. 
* From the datasheet of this chip : 
{{<callout>}}
READ : The AT28C16 is accessed like a Static RAM.
When CE and OE are low and WE is high, the data stored
at the memory location determined by the address pins is
asserted on the outputs. The outputs are put in a high
impedance state whenever CE or OE is high. This dual line
control gives designers increased flexibility in preventing
bus contention. 
{{</callout>}}  

Which means we will first need to send the commands to enable read   
`set_oe_pin(0)` --> Low  
`set_ce_pin(0)` --> Low  
`set_we_pin(5)` --> High   

## First Attempt
* My first thought was to read all the memory address, expecting some data stored in it, here is the script to brute all the addresses of the memory :

```python
from pwn import * 
import warnings
from tqdm import tqdm
warnings.filterwarnings('ignore')

arr = []
for i in tqdm(range(0x800)):
    addr = list(map(int, bin(i)[2:].rjust(11, '0')))
    p.sendlineafter(">", "set_address_pins(" + str(addr) + ")")
    p.sendlineafter(">", "read_byte()")
    if i == 0 :
        p.recv()
        p.recv()
    data = p.recvline()
    if i == 0 :
        arr.append(eval(data.split(b' ')[1].decode()))
    else :
        arr.append(eval(data.split(b' ')[2].decode()))

print(arr)
```  

* Offcourse the array was completely filled with zeros, and there seemed a deadend to this challenge. 
* But afterwards when I was going through the datasheet of this chip to read more stuff about it I, came across this paragraph which I had missed earlier : 
{{<callout>}}
DEVICE IDENTIFICATION : An extra 32 bytes of
EEPROM memory are available to the user for device identification. By raising A9 to 12 ± 0.5V and using address
locations 7E0H to 7FFH the additional bytes may be written
to or read from in the same manner as the regular memory
array. 
{{</callout>}}  

## Final realisation 
* `Extra 32 bytes` definitely justified that this is where the flag was stored

* So I again wrote the script to read address `0x7E0` to `0x7FF` while making sure `A9` was set to `12V` 

* Since `A10` is MSB and `A0` is LSB I just had to change the last 5 bits while keeping the upper 6 bits constant because `0x7E0 == 11111100000b` and `0x7FF == 11111111111b`  
* This is the final script to read those addresses and get the flag : 

```python
from pwn import * 
import warnings
from tqdm import tqdm
warnings.filterwarnings('ignore')

p = remote("94.237.60.37", 42096)

p.sendlineafter('>', "set_oe_pin(0)")
p.sendlineafter('>', "set_ce_pin(0)")
p.sendlineafter('>', "set_we_pin(5)")

arr = []
for i in tqdm(range(32)):
    addr = list(map(int, bin(i)[2:].rjust(5, '0')))
    for j in range(5):
        if addr[j] == 1 :
            addr[j] = 5
    addr = [5, 12, 5, 5, 5, 5] + addr #A9 -> 12 
    p.sendlineafter(">", "set_address_pins(" + str(addr) + ")")
    p.sendlineafter(">", "read_byte()")
    if i == 0 :
        p.recv()
        p.recv()
    data = p.recvline() 
    if i == 0 :
        arr.append(eval(data.split(b' ')[1].decode()))
    else :
        arr.append(eval(data.split(b' ')[2].decode()))

print(''.join(chr(i) for i in arr))
```

---

#### Flag : `HTB{AT28C16_EEPROM_s3c23t_1d!!!}`  
  






