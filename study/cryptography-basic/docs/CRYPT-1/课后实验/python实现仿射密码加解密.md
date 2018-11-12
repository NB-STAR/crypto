## python实现仿射密码加解密

### 【目的】
1. 仿射密码加密
2. 仿射密码解密

### 【环境】
- 操作机：Ubuntu

### 【工具】
- Sublime Text
- python2


### 【原理】

**加解密：**

它的加密函数是$C=(aM+b) mod\space 26$，其中
- 数字对（a，b）为密钥
- a和26互素，既：$gcd⁡(a,26)=1$
- b为小于26的正整数
- 在英文中有26个字母，因此是 $mod\space 26$

它的解密函数是$M=a^{−1} (C−b)mod\space 26$

### 【实验步骤】

#### 参考代码 python2

**1. 加解密：**

```python
# -*- coding: utf-8 -*-

import string

plaintext_ = string.ascii_lowercase
ciphertext_ = string.ascii_uppercase

#加密算法

def encryption(plaintext):
    cipherarr = [0 for i in range(len(plaintext))]
    plaintext_list = list(plaintext)

    j = 0
    for plaintext_item in plaintext_list:
        for i in range(len(plaintext_)):
            if plaintext_item == plaintext_[i]:
                ciphertext = (11*i+4)%26
                cipherarr[j] = ciphertext_[ciphertext]
                j = j+1

    cipher = ''.join(cipherarr)
    return cipher

while True:
    plaintext = raw_input('请输入明文：')
    cipher = encryption(plaintext)
    if plaintext == 'exit':
        break
    print '密文是:',cipher

# 解密算法
def decryption(ciphertext):
    plaintext_arr = [0 for i in range(len(ciphertext))]
    cipherlist = list(ciphertext)

    j = 0
    for cipheritem in cipherlist:
        for i in range(len(ciphertext_)):
            if cipheritem == ciphertext_[i]:
                plaintext = (19*i-24)%26
                plaintext_arr[j] = plaintext_[plaintext]
                j = j+1

    plain = ''.join(plaintext_arr)
    return plain

while True:
    ciphertext = raw_input('请输入密文：')
    plain = decryption(ciphertext)
    if ciphertext == 'EXIT':
        break
    print '明文输出为：',plain

print "请选择加密或解密，加密输入e，解密输入d"
a = raw_input()
if a == "e":
    plaintext = raw_input('请输入明文：')
    cipher = encryption(plaintext)
    print '密文是:',cipher
elif a == "d":
    ciphertext = raw_input('请输入密文：')
    plain = decryption(ciphertext)
    print '明文输出为：',plain
else:
    print "输入的字母有误"

```

- 创建一个python文件，拷贝参考代码
![](files/2018-06-14-17-57-59.png)

- 在文件所在文件夹打开terminal，并运行python文件
![](files/2018-06-14-18-00-03.png)


### 【总结】
- 通过学习实验，掌握实现仿射密码加解密的方法。