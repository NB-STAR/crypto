## Baby DLP (crypto)

我们可以拿到题目的服务源代码，阅读源代码，看到加密的方式是：我们向服务器发送一个十六进制数`s`，服务器返回`c = pow(g, m ^ s, p)`。由题目可知，我们可能需要解决这个离散对数问题。

输入: $s$
输出: $c=2^{m\oplus s}(mod\space p)$

当 $s=0$时，$m\oplus s=m$，因为0或者1 XOR 0是它们本身，所以$2^m \cdot 2^n(mod\space p)=c_0$

当$s=1$时，有两种情况：
- 如果m的最后一个比特是0，那么，$2^{m\oplus s}(mod\space p)=2^{m+1}(mod\space p)$
- 如果m的最后一个比特是1，那么，$2^{m\oplus s}(mod\space p)=2^{m-1}(mod\space p)$

当$s=2$时，有两种情况：
- 如果m的最后一个比特是0，那么，$2^{m\oplus s}(mod\space p)=2^{m+2}(mod\space p)=2^m\cdot 2^2(mod \space p)$

- 如果m的最后一个比特是1，那么，$2^{m\oplus s}(mod\space p)=2^{m-2}(mod\space p)=2^m\cdot 2^{-2}(mod \space p)$

当$s=n$时，有两种情况：
- 如果m的最后一个比特为0，那么，$2^{m\oplus s}(mod\space p)=2^{m+n}(mod\space p)=2^m\cdot 2^n(mod \space p)=c_n$

- 如果m的最后一个比特是1，那么，$2^{m\oplus s}(mod\space p)=2^{m-n}(mod\space p)=2^m\cdot 2^{-n}(mod \space p)=c_n$

所以，我们可以通过这个方法去猜出$m$的每一位

基于如下公式：

$2^m\cdot 2^n(mod\space p)=(2^m(mod\space p)\cdot 2^n(mod\space p))(mod\space p)=(c_0\cdot 2^n(mod\space p))(mod\space p)=c_n$

$2^m\cdot 2^{-n}(mod \space p)=(2^m(mod\space p)\cdot 2^{-n}(mod\space p))(mod\space p)=(c_n\cdot2^n(mod\space p))(mod\space p)=c_0$

我们可以得出：

当 $(c_0\cdot 2^n(mod\space p))(mod\space p)=c_n$时，第n位m的值为1；当 $(c_n\cdot2^n(mod\space p))(mod\space p)=c_0$时，第n位m的值为0。

因此，我们可以推断出m的每一位

接下来开始写对应的脚本：

```python
import pwn
import os
from Crypto.Util.number import *

p = 160634950613302858781995506902938412625377360249559915379491492274326359260806831823821711441204122060415286351711411013883400510041411782176467940678464161205204391247137689678794367049197824119717278923753940984084059450704378828123780678883777306239500480793044460796256306557893061457956479624163771194201
g = 2

bits = ''
if __name__ == '__main__':
	
	r = pwn.remote('127.0.0.1',28459) 

	r.sendline(hex(0))
	c0 = int(r.readline().strip(), 16)

	for n in range(0x200):
		r.sendline(hex(1<<n))
		cn = int(r.readline().strip(), 16)

		if (c0 * pow(g, 1<<n, p))%p == cn:
			bits = '0' + bits

		if (cn * pow(g, 1<<n, p))% p == c0:
			bits = '1' + bits

		print 'n:',n
		print 'bits',hex(int(bits, 2))

	print 'flag',long_to_bytes(int(bits,2))

```


