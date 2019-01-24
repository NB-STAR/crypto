# WTF


RSA的wiener attack攻击，但需要先用1337解码一下

exp.py
```
import gmpy2
from Crypto.Util.number import *
n = 'lObAbAbSBlZOOEBllOEbblTlOAbOlTSBATZBbOSAEZTZEAlSOggTggbTlEgBOgSllEEOEZZOSSAOlBlAgBBBBbbOOSSTOTEOllbZgElgbZSZbbSTTOEBZZSBBEEBTgESEgAAAlAOAEbTZBZZlOZSOgBAOBgOAZEZbOBZbETEOSBZSSElSSZlbBSgbTBOTBSBBSOZOAEBEBZEZASbOgZBblbblTSbBTObAElTSTOlSTlATESEEbSTBOlBlZOlAOETAZAgTBTSAEbETZOlElBEESObbTOOlgAZbbOTBOBEgAOBAbZBObBTg'

e = 'lBlbSbTASTTSZTEASTTEBOOAEbEbOOOSBAgABTbZgSBAZAbBlBBEAZlBlEbSSSETAlSOlAgAOTbETAOTSZAZBSbOlOOZlZTETAOSSSlTZOElOOABSZBbZTSAZSlASTZlBBEbEbOEbSTAZAZgAgTlOTSEBEAlObEbbgZBlgOEBTBbbSZAZBBSSZBOTlTEAgBBSZETAbBgEBTATgOZBTllOOSSTlSSTOSSZSZAgSZATgbSOEOTgTTOAABSZEZBEAZBOOTTBSgSZTZbOTgZTTElSOATOAlbBZTBlOTgOSlETgTBOglgETbT'

c = 'SOSBOEbgOZTZBEgZAOSTTSObbbbTOObETTbBAlOSBbABggTOBSObZBbbggggZZlbBblgEABlATBESZgASBbOZbASbAAOZSSgbAOZlEgTAlgblBTbBSTAEBgEOEbgSZgSlgBlBSZOObSlgAOSbbOOgEbllAAZgBATgEAZbBEBOAAbZTggbOEZSSBOOBZZbAAlTBgBOglTSSESOTbbSlTAZATEOZbgbgOBZBBBBTBTOSBgEZlOBTBSbgbTlZBbbOBbTSbBASBTlglSEAEgTOSOblAbEgBAbOlbOETAEZblSlEllgTTbbgb'

lookup = ['O', 'l', 'Z', 'E', 'A', 'S', 'b', 'T', 'B', 'g']

def decode(x):
    ans = ''
    for c in x:
        ans += str(lookup.index(c))
    return int(ans)

n = decode(n)
e = decode(e)
c = decode(c)

def cf_expansion(n, d):
    e = []

    q = n // d
    r = n % d
    e.append(q)

    while r != 0:
        n, d = d, r
        q = n // d
        r = n % d
        e.append(q)

    return e

def convergents(e):
    n = [] # Nominators
    d = [] # Denominators

    for i in range(len(e)):
        if i == 0:
            ni = e[i]
            di = 1
        elif i == 1:
            ni = e[i]*e[i-1] + 1
            di = e[i]
        else: # i > 1
            ni = e[i]*n[i-1] + n[i-2]
            di = e[i]*d[i-1] + d[i-2]

        n.append(ni)
        d.append(di)
        yield (ni, di)

def solve(b, c):
    k = b * b - 4 * 1 * c
    if k < 0: return []
    sk, complete = gmpy2.iroot(k, 2)
    if not complete: return []
    return [int((-b + sk) // 2), int((-b - sk) // 2)]

def wiener(e, n):
    kd = convergents(cf_expansion(e, n))
    for i, (k, d) in enumerate(kd):
        if k == 0: continue
        phi = (e * d - 1) // k
        roots = solve(phi - n - 1, n)
        if len(roots) == 2:
            p, q = roots
            if p * q == n:
                return (p, q)

p, q = wiener(e, n)

r = (p - 1) * (q - 1)
d = inverse(e, r)
m = pow(c, d, n)
print(long_to_bytes(m))
```