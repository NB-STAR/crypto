# holywater

[https://galhacktictrendsetters.wordpress.com/2018/09/17/csaw-quals-2018-holywater/](https://galhacktictrendsetters.wordpress.com/2018/09/17/csaw-quals-2018-holywater/)

exp.py
```py
from cryptography.fernet import Fernet
from lattice import Lattice
 
GHEX = 'e002af4dec89cd6c063bca41ac24cb0636a23dcd00641990a58aafa89a62e386'
PHEX = '5e91a05d58e23a1d891f576040ff7bc37bfbfd1d1fcf92c02cbd0f4cdc8ea284'
CHEX = '15ff1eda110c670bdd76dc28e222d80aedaa5c6f82ec15758d8f04e4508b34fb'
JHEX = '41ea7e0f2d4e4491fac0aabdd8cb1d4613bef7a29ab7fe0d60b971d3f61ad918'
 
CIPHERTEXT = 'gAAAAABbm_jeozf2NnpedlvFzatVxOqhalOf5w1aZzgOLZ2Qx9sBakb9CK_hAAPbfjD0GDXQUrdnl_0SGQw1U1c4oTRJfO_awTloqXVUTBpHGxhP0BGWeN0='
P = 4294967279
 
def write_in_basis(basis, v):
    mat = matrix(GF(P), basis)
    assert mat.rank() == 4
    b = matrix(GF(P), [v])    
    return list(mat.solve_left(b)[0])
     
 
def solve():
    g = Lattice.from_str(GHEX)
    p = Lattice.from_str(PHEX)
    c = Lattice.from_str(CHEX)
    j = Lattice.from_str(JHEX)
    one = Lattice.absolute()
     
    basis = [p.coords(), (g*p).coords(), (p*g).coords(), (g*(p*g)).coords()]
     
    a = write_in_basis(basis, c.coords())
    c1 = one.dilate(a[0]) + g.dilate(a[1] + a[2]) + (g*g).dilate(a[3])
     
    basis2 = [one.coords(), g.coords(), p.coords(), (g*p).coords()]
    b = write_in_basis(basis2, j.coords())
    ans = (one.dilate(b[0]) + g.dilate(b[1]))*c1 + (one.dilate(b[2]) + g.dilate(b[3]))*c
 
    key = str(ans).decode('hex').encode('base64')
    f = Fernet(key)
    msg = f.decrypt(CIPHERTEXT)
    print msg
     
 
if __name__ == '__main__':
    solve()
```