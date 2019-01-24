# Chop_Suey

RSA中已知dp,dq,q,p,c求m的问题
分析文章:[http://skysec.top/2018/08/25/RSA%E4%B9%8B%E6%8B%92%E7%BB%9D%E5%A5%97%E8%B7%AF-2/](http://skysec.top/2018/08/25/RSA%E4%B9%8B%E6%8B%92%E7%BB%9D%E5%A5%97%E8%B7%AF-2/)

exp.py
```py
import binascii
import struct

# return (g, x, y) a*x + b*y = gcd(x, y)
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def decryptRSA(p,q,e,ct):
	# compute n
	n = p * q
	phi = (p - 1) * (q - 1)	
	gcd, a, b = egcd(e, phi)
	d = a
	print "d: " + str(d)
	pt = pow(ct, d, n)
	return pt

def encryptRSA(p,q,e,pt):
	# compute n
	n = p * q
	phi = (p - 1) * (q - 1)
	gcd, a, b = egcd(e, phi)
	d = a
	print "d: " + str(d)
	ct = pow(pt, e, n)
	return ct


def convert(int_value):
   encoded = format(int_value, 'x')
   length = len(encoded)
   encoded = encoded.zfill(length+length%2)
   return encoded.decode('hex')

# x = mulinv(b) mod n, (x * b) % n == 1
def mulinv(b, n):
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def main():
	# By implementing Chinese remainder algorithm
	# 1) p and q are the primes
	# 2) dp = d mod (p - 1)
	# 3) dq = d mod (q - 1)
	# 4) Qinv = 1/q mod p *This is not integer devision but multiplicative inverse
	# 5) m1 = pow(c, dp, p)
	# 6) m2 = pow(c, dq, q)
	# 7-1) h = Qinv(m1 - m2) mod p  ; if m1 < m2
	# 7-2) h = Qinv * (m1 + q/p) 
	# 8) m = m2 + hq

	# m = 65
	# p = 61
	# q = 53
	# dp = 53
	# dq = 49
	# c = 2790

	p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229
	q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469
	dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929
	dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041
	c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852

	Qinv = mulinv(q,p)
	print "Qinv: " + str(Qinv)

	m1 = pow(c, dp, p)
	print "m1: " + str(m1)

	m2 = pow(c, dq, q)
	print "m2: " + str(m2)

	h = (Qinv * (m1 - m2)) % p
	print "h: " + str(h)

	m = m2 + (h*q)
	print "m: " + str(int(m))

	hexadecimals = str(hex(m))[2:-1]
	print "solved: " + str(binascii.unhexlify(hexadecimals))
	# solved: Theres_more_than_one_way_to_RSA

if __name__ == "__main__":
	main()

```

