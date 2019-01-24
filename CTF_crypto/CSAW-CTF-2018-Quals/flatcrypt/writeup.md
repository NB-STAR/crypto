# flatcrypt

这题属于CRIME attack (https://en.wikipedia.org/wiki/CRIME)

例如:
test.py
```python
import zlib
import sys
PROBLEM_KEY = 'neko'
print PROBLEM_KEY+sys.argv[1]
print len(zlib.compress(PROBLEM_KEY+sys.argv[1]))
```
爆破最后一位:
```py
python test.py `python -c 'print "a"*20'`
nekoaaaaaaaaaaaaaaaaaaaa
14

python test.py `python -c 'print "o"*20'`
nekooooooooooooooooooooo
13
```
只有'o'的时候压缩后的长度最短，为13。
爆破最后两位:
```python
python test.py `python -c 'print "io"*20'`
nekoioioioioioioioioioioioioioioioioioioioio
15

python test.py `python -c 'print "ko"*20'`
nekokokokokokokokokokokokokokokokokokokokoko
14
```

exp.py
```py
from pwn import *
import string
dict=string.ascii_lowercase+'_'
r=remote('127.0.0.1',32770)
flag=''
count=[0 for i in dict]
for i in range(32):
    for j in range(len(dict)):
        payload=(dict[j]+flag)*20
        junk= r.recvline()
        r.sendline(payload)
        l=r.recvline()[-2]
        count[j]=ord(l)
    print count,sorted(list(set(count)))
    for k in dict:
        print ' ', k,
    if len(sorted(list(set(count))))==3:
        print '\npls choose %s or %s: '%(dict[count.index(sorted(list(set(count)))[0])],dict[count.index(sorted(list(set(count)))[1])])
        next_letter=raw_input().rstrip('\n')
        flag=next_letter+flag
        print flag
    else:
        flag=dict[count.index(min(count))]+flag
    print '\n[*]flag:%s\n'%flag
```