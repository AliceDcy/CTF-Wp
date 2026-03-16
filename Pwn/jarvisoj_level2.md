# jarvisoj_level2
## 考点
栈溢出

## 解题思路
1. 检查保护：`checksec` 输出

数据段不可执行，但没有开启栈保护机制，考虑栈溢出

1. 分析漏洞：
连接靶机

IDA分析level2文件，根据汇编代码可知，main函数中的 system 指令地址 sys1_addr=0x804849E，vuln函数中的 system 指令地址 sys2_addr=0x804845c
![alt text](<./images/4.png>)
![alt text](<./images/2.png>)
Hint：String 显示'/bin/sh'存储地址 bin_addr=0x0804A024，提示利用程序中已有的call system 指令地址，更改参数为"/bin/sh"，虽然两个 call 指令都跳转到同一个 system.plt，但利用 call 指令本身会将下一条指令的地址压栈，所以能成功；而直接使用 system.plt 没有自动压栈返回地址的过程
![alt text](<./images/5.png>)

1. 构造payload：

由于buf占136字节，ebp地址占4字节，返回地址在buf+140处起始
![alt text](<./images/6.png>)
执行流程：
1.vulnerable_function 返回时执行 ret，从栈顶弹出返回地址（即 sys_addr），并跳转到该地址。此时栈顶（esp）指向 bin_addr。

2.执行到 sys_addr 处的 call system 指令：
call 将下一条指令地址压栈（esp -= 4，写入该地址），此时 esp 指向新压入的返回地址，而 bin_addr 位于 esp+4。
然后跳转到 system.plt。

3.system 函数被调用，它按照 32 位调用约定，从栈上获取参数：第一个参数位于返回地址之后，即 [esp+4]，正好是 bin_addr。因此成功执行 system("/bin/sh")。

1. 获取flag
![alt text](<./images/1.png>)

## 脚本
```python
from pwn import*

r=remote('node5.buuoj.cn',27121)

payload=b'I'*140+p32(0x804845C)+p32(0x0804A024)

r.sendline(payload)
r.interactive()

```