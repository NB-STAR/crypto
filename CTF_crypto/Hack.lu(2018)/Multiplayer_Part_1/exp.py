# coding=utf-8
import json
from pwn import *
def json_input(x, y, c, d, groupID):
    dict1 = {'x': str(x), 'y': str(y), 'c': str(c), 'd': str(d), 'groupID': str(groupID)}
    return json.dumps(dict1)


param = {   "hacklu":
            ((889774351128949770355298446172353873, 12345, 67890),
            # Generator of Subgroup of prime order 73 bits, 79182553273022138539034276599687 to be excact
            (238266381988261346751878607720968495, 591153005086204165523829267245014771),
            # challenge Q = xP, x random from [0, 79182553273022138539034276599687)
            (341454032985370081366658659122300896, 775807209463167910095539163959068826)
            )
        }

(p, a, b), (px, py), (qx, qy) = param["hacklu"]
E = EllipticCurve(GF(p), [a, b])

P = E((px, py))
Q = E((qx, qy))

# 随便起个groupID，因为是本地，不会和别的队伍冲突
groupID=233333 

# X=0*P+0*Q
# print X
io=remote('127.0.0.1','23426')

for i in range(1,202):
    X=i*P+i*Q
    x=X[0]
    y=X[1]
    c=d=i
    data=json_input(x,y,c,d,groupID)
    io.sendline(data)
    print io.recv()
